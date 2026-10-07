# Kế hoạch Hoàn thiện Thuật toán Quét File (ClamAV 1.5.4 Parity Plan)

Tài liệu này phân tích chi tiết các điểm sai lệch, sự khác biệt và các cơ chế đặc thù ("kỳ lạ nhưng có chủ đích") giữa mã nguồn gốc C/C++ của **ClamAV 1.5.4** (`libclamav`) và bộ máy quét C# **ClamGuard.Net**, đồng thời đưa ra kế hoạch triển khai (Implementation Plan) từng bước để tối ưu hóa và chuẩn hóa toàn bộ thuật toán quét file.

---

## 1. Phân tích hiện trạng & Các điểm "Kỳ lạ" trong Thuật toán ClamAV C/C++

Qua rà soát mã nguồn ClamAV 1.5.4 (`libclamav/scanners.c`, `matcher.c`, `matcher-ac.c`):

| Thành phần | Thuật toán ClamAV 1.5.4 (C/C++) | Hiện trạng ClamGuard.Net (C#) | Đánh giá & Rủi ro |
| :--- | :--- | :--- | :--- |
| **1. Cửa sổ trượt (Sliding Window)** | Dùng sliding window `SCANBUFF` (128KB - 1MB), bước trượt **chồng lấn** `offset += bytes - maxpatlen`. Reset AC state mỗi window. | Duy trì biến `ref int acState` qua các chunk của `Stream`, dùng rolling lookbehind cho flexible pattern. | Nếu pattern dài hơn buffer hoặc trượt boundary với regex/flexible offset, có thể sót hoặc lệch offset. |
| **2. Băm Hash song song** | Băm MD5/SHA1/SHA256 chung vòng lặp với Matcher, loại bỏ đoạn overlap `buff + maxpatlen * (offset != 0)` để không băm trùng lặp. | Băm độc lập qua `IncrementalHash.AppendData(buffer, 0, read)`. | C# tách riêng stream băm toàn vẹn là chuẩn cho hash độc lập, nhưng tốn 2 luồng xử lý riêng nếu stream không seek được. |
| **3. Thứ tự quét (Pre vs Raw vs Post)** | **3 tầng rõ rệt:**<br>1. *Pre-raw:* Archives, HWP3, XDP, OneNote.<br>2. *Raw:* Aho-Corasick + Hash.<br>3. *Post-raw:* PE unpack (UPX, FSG), ELF/Mach-O unpack, script normalize. | Đã áp dụng `requiresSpecializedPreRaw` và `requiresContainerExpansion`, nhưng PE scan vẫn chia nhỏ thành `PeSpecializedMatcher` chạy sau. | Cần đồng bộ chặt chẽ thứ tự ưu tiên khi có Self-Protection Database (`.sdb`): SDB bắt buộc chạy Raw trước mọi parser. |
| **4. Phát hiện kiểu nhúng (Embedded Type Detection)** | Khi chạy `scanraw()`, AC chạy cả cờ `AC_SCAN_FT`. Nếu tìm thấy magic file lồng (ví dụ SFX ZIP trong PE, MHTML trong data), ClamAV đổi type ngay tại layer hiện tại và bung file. | `DetectType` chỉ probe ban đầu (1028 bytes đầu + 32KB ISO/UDF). Quá trình streaming raw không hỗ trợ đổi kiểu file khi gặp magic giữa file. | Bỏ sót các payload mã độc dạng Self-Extracting (SFX) hoặc tài liệu nhúng sâu trong file nhị phân. |
| **5. Trì hoãn Logical Signatures (Deferred LDB)** | Trong lúc quét AC/BM chỉ ghi nhận `matchstart`/`matchend` của các sub-signatures vào `mdata`. Sau khi quét xong toàn bộ file mới chạy `cli_lsig_eval`. | C# đang materialize toàn bộ file vào `fullData` nếu có Logical Signature hoặc NDB không stream được. | Gây tốn RAM lớn (Out of Memory) khi gặp file lớn cần match LDB; cần cơ chế streaming LDB sub-signature tracking. |
| **6. Khử trùng lặp & Giới hạn an toàn** | Bỏ qua file `<= 5 bytes` (`CL_SUCCESS`). Kiểm tra Cache Hash (`clean_cache_check`) trước khi parse. Giới hạn `MaxRecursion`, `MaxScanSize`. | Đã có `info.Length == 0` và `Limits`, nhưng chưa có bỏ qua file `<= 5 bytes` như ClamAV chuẩn; cơ chế clean cache chưa tích hợp đầy đủ. | Tốn tài nguyên quét các file rác < 6 bytes. |

---

## 2. Mục tiêu Triển khai (Objectives)

1. **Chuẩn hóa cơ chế Sliding Window & Buffer Overlap:** Đảm bảo không bỏ sót bất kỳ signature nào nằm vắt ngang qua ranh giới 2 chunk buffer.
2. **Hỗ trợ Embedded Type Detection trong lúc quét Stream:** Nhận diện và tự động bẻ nhánh bóc tách các định dạng nhúng (SFX ZIP, embedded PDF, OLE10, MHTML) khi Aho-Corasick bắt gặp magic file type.
3. **Tối ưu hóa Deferred LDB Engine cho Stream:** Không cần nạp toàn bộ file vào bộ nhớ RAM khi gặp Logical Signatures; chuyển sang cơ chế ghi nhận sub-signature hits theo offset trong quá trình stream.
4. **Đồng bộ hóa triệt để thứ tự quét theo ClamAV 1.5.4 Spec:**
   - Pre-raw Container Parser (Archive, OneNote, HWP3, XDP)
   - Self-Protection DB (`.sdb`) check
   - Raw Pattern Matcher (AC + Hash)
   - Embedded Layer Recursion
   - Post-raw Unpackers (PE sections, UPX, Authenticode, Mach-O slices)

---

## 3. Lộ trình Triển khai Chi tiết (Phased Implementation Plan)

### Giai đoạn 1: Chuẩn hóa Engine Stream & Sliding Window (CompiledSignatureSet & ScannerEngine)
- **Mục tiêu:** Khắc phục triệt để hiện tượng sót pattern tại ranh giới buffer.
- **Nội dung công việc:**
  1. Kiểm tra kích thước `maxpatlen` lớn nhất trong cây Aho-Corasick khi `Build()`.
  2. Thiết lập độ dài overlap tối thiểu bằng `Max(maxpatlen, maxFlexibleLookbehind)` cho buffer trượt.
  3. Bổ sung quy tắc bỏ qua file `<= 5 bytes` chuẩn hóa theo `cli_magic_scan`:
     ```csharp
     if (info.Length <= 5)
         return new ScanResult(ScanVerdict.Clean, path, rootType, [], info.Length, started.Elapsed, ...);
     ```
  4. Đảm bảo tính toán Relative Offset (`EP+n`, `EOF-n`, `SL+n`) chính xác ngay cả khi quét stream có chunking.

### Giai đoạn 2: Cơ chế Embedded File-Type Re-detection (Trong luồng Raw Scan)
- **Mục tiêu:** Mô phỏng cờ `AC_SCAN_FT` của ClamAV để phát hiện file nhúng trong raw stream.
- **Nội dung công việc:**
  1. Tích hợp bộ nhận diện Magic (`FileTypeMagicDetector`) vào luồng quét AC hoặc song song trong `MatchStreamAsync`.
  2. Nếu phát hiện thấy chữ ký định dạng container tại offset > 0 (ví dụ `PK\x03\x04` của ZIP trong file PE/EXE hoặc `%PDF-` trong doc):
     - Đánh dấu layer hiện tại có container nhúng.
     - Trích xuất sub-stream từ offset tương ứng đưa vào `ArchiveScanner` với độ sâu đệ quy tăng lên 1 tầng (`recursion_level + 1`).
  3. Bổ sung các test case kiểm tra SFX (Self-Extracting ZIP/RAR) và file nhúng.

### Giai đoạn 3: Tối ưu hoá Đánh giá Logical Signature (Deferred LDB Tracking)
- **Mục tiêu:** Giảm tiêu thụ RAM và xóa bỏ việc ép buộc đọc toàn bộ file (`fullData = ReadFullFileAsync`) đối với các file lớn.
- **Nội dung công việc:**
  1. Xây dựng cấu trúc `LdbStreamTracker` tương đương `struct cli_ac_data`:
     - Theo dõi mảng bitset / offset của các sub-signature (`part0`, `part1`,...) đã thỏa mãn khi stream đi qua.
     - Lưu trữ EntryPoint (EP), FileSize (EOF), và Section Headers (đối với PE) từ đầu stream.
  2. Khi stream kết thúc:
     - Chạy hàm đánh giá biểu thức logic `LdbRuntime.Evaluate()` dựa trên bảng hit offsets thu thập được mà không cần quét lại toàn bộ mảng byte.
  3. Giữ đường dẫn `fullData` chỉ cho các trường hợp bắt buộc phải có toàn bộ cấu trúc (như trích xuất Macro VBA, giải nén PDF Streams phức tạp).

### Giai đoạn 4: Hoàn thiện Thứ tự Ưu tiên & Khử trùng lặp (Verdict & Cache Pipeline)
- **Mục tiêu:** Đảm bảo kết quả trả về đồng nhất 100% với `clamscan`.
- **Nội dung công việc:**
  1. **Clean Hash Cache:** Bổ sung cơ chế lưu trữ SHA256 các file đã xác nhận Clean vào Memory Cache ngắn hạn. Nếu file có hash trùng và thời gian sửa đổi không đổi, trả kết quả tức thì.
  2. **False Positive & Whitelist:** Kiểm tra `.fp` và `.sfp` trước khi gán nhãn `Malicious`. Nếu trúng whitelist, chuyển verdict thành `Trusted` và dừng đệ quy.
  3. **Early Exit Logic:** Tôn trọng cờ `CollectAllMatches` (mặc định dừng ngay khi gặp mẫu virus đầu tiên ở bất kỳ layer nào, giúp tăng tốc độ quét lên 3-5x đối với file nhiễm độc).

---

## 4. Kế hoạch Kiểm thử & Đo lường (Verification & Regression Matrix)

| Kịch bản kiểm thử | Mục đích kiểm tra | Kết quả mong đợi |
| :--- | :--- | :--- |
| **Boundary Cross Test** | Signature cố ý nằm cắt ngang ranh giới giữa Chunk 1 và Chunk 2 (offset 4095-4100). | Phát hiện thành công 100%, không bị sót. |
| **SFX ZIP Inside PE** | File EXE chứa tệp nén ZIP ở đuôi (Self-extracting). | Nhận diện được cả chữ ký EXE và giải nén được file bên trong ZIP. |
| **Small Files (0-5 bytes)** | Quét các file 0 byte, 1 byte, 5 bytes. | Trả về `Clean` ngay lập tức, không tốn I/O băm hash hay duyệt AC. |
| **Relative Offset LDB** | Logical signature yêu cầu `EP+16` hoặc `EOF-32`. | Khớp chính xác theo vị trí cấu trúc PE và kích thước stream. |
| **Memory Stress (File 500MB)** | Quét file ISO/EXE dung lượng lớn với luật LDB. | Bộ nhớ tiến trình RAM không tăng vọt (không materialized toàn bộ file nếu không cần thiết). |

---

## 5. Danh sách Tệp cần Tác động trong Dự án

- [`src/ClamGuard.Scanner/ScannerEngine.cs`](file:///c:/Users/quock/Downloads/ClamGuard-Net-with-Antivirus-WPF/src/ClamGuard.Scanner/ScannerEngine.cs): Đồng bộ hóa luồng điều phối chính, tích hợp bypass file <= 5 bytes và dispatch embedded layers.
- [`src/ClamGuard.Signatures/Matching/CompiledSignatureSet.cs`](file:///c:/Users/quock/Downloads/ClamGuard-Net-with-Antivirus-WPF/src/ClamGuard.Signatures/Matching/CompiledSignatureSet.cs): Nâng cấp sliding window overlap, cơ chế stream lookbehind.
- [`src/ClamGuard.Scanner/LdbRuntime.cs`](file:///c:/Users/quock/Downloads/ClamGuard-Net-with-Antivirus-WPF/src/ClamGuard.Scanner/LdbRuntime.cs): Tách logic thu thập sub-signature hit ra khỏi logic nạp mảng `byte[]` toàn phần.
- [`src/ClamGuard.Scanner/ArchiveScanner.cs`](file:///c:/Users/quock/Downloads/ClamGuard-Net-with-Antivirus-WPF/src/ClamGuard.Scanner/ArchiveScanner.cs): Tối ưu hóa việc gọi quét recursive layers từ stream offset.
