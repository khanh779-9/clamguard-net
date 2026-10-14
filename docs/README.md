# 📚 Documentation — ClamGuard.NET

Thư mục này chứa **tài liệu phân tích và đặc tả** của dự án. Tất cả tài liệu viết bằng
**Markdown (CommonMark + GFM)**, tiếng Việt, đặt ngay trong thư mục này.

## Danh mục tài liệu

### Đặc tả định dạng

| Tài liệu | Nội dung |
|----------|----------|
| [`daily_CVD_Signature_Format_Analysis.md`](./daily_CVD_Signature_Format_Analysis.md) | Đặc tả định dạng `daily.cvd` — container CVD, 23 file DB con, cú pháp từng loại chữ ký (hash, NDB, LDB, CDB, IDB, CRB, FTM, phishing, DCONF…), bẫy từ dữ liệu thật, hướng dẫn triển khai C#, kế hoạch kiểm thử. Gộp từ 2 bản phân tích độc lập + đối chiếu source ClamAV 1.5.4. |

### Kiến trúc từng project

| Tài liệu | Project | Nội dung |
|----------|---------|----------|
| [`project-ClamGuard.Core.md`](./project-ClamGuard.Core.md) | `ClamGuard.Core` | Nền tảng chung: hex codec, model domain (ScanOptions/ScanLimits/Detection/ScanResult), chính sách lọc PUA/heuristic, giới hạn quét. |
| [`project-ClamGuard.Signatures.md`](./project-ClamGuard.Signatures.md) | `ClamGuard.Signatures` | Parse chữ ký ClamAV (.hdb/.ndb/.ldb/.cdb/.idb/…) + engine matching: Aho-Corasick, BMH, hex pattern, prefilter logical, compiled set streaming. |
| [`project-ClamGuard.Scanner.md`](./project-ClamGuard.Scanner.md) | `ClamGuard.Scanner` | Pipeline quét: file-type detection, archive/container, PE, image fuzzy hash, logical runtime, ScanHost hosting. |
| [`project-ClamGuard.Database.md`](./project-ClamGuard.Database.md) | `ClamGuard.Database` | Nạp CVD/CLD, đặc thù DB, ignore-list, DCONF, verify chữ ký (RSA-PSS/CMS), update CDIFF. |
| [`project-ClamGuard.Bytecode.md`](./project-ClamGuard.Bytecode.md) | `ClamGuard.Bytecode` | Máy ảo bytecode ClamAV (.cbc): parser định dạng, VM có fuel/depth/runtime caps, API layer. |
| [`project-ClamGuard.Yara.md`](./project-ClamGuard.Yara.md) | `ClamGuard.Yara` | Emulator subset YARA (strings + conditions cơ bản), cơ chế warning cho construct chưa hỗ trợ. |
| [`project-ClamGuard.Antivirus.md`](./project-ClamGuard.Antivirus.md) | `ClamGuard.Antivirus` | Ứng dụng WPF: MVVM, services (engine, realtime, quarantine, memory scan, settings), i18n, theme, toolkit. |

## Tài liệu tham chiếu ngoài thư mục

- [`README.md`](../README.md) — tổng quan dự án, tính năng, cách build/chạy test.
- Mã nguồn ClamAV 1.5.4 dùng để đối chiếu: bản cài đặt cục bộ (nếu có), hoặc
  [github.com/Cisco-Talos/clamav](https://github.com/Cisco-Talos/clamav) tag tương ứng.

## Quy ước viết tài liệu trong thư mục này

Áp dụng cho mọi file `.md` thêm vào sau này:

1. **Ngôn ngữ**: tiếng Việt; thuật ngữ kỹ thuật (class, format, CLI flag) giữ nguyên tiếng Anh.
2. **Cấu trúc**: mỗi file có tiêu đề `#` duy nhất, mục lục khi dài hơn ~200 dòng,
   đánh số mục bằng `##`.
3. **Nhãn nguồn thông tin** khi tài liệu chứa kết quả phân tích/đo đạc:

   | Nhãn | Ý nghĩa |
   |------|---------|
   | 📏 Đo từ dữ liệu | Số liệu đo trực tiếp trên một đối tượng cụ thể (ghi rõ bản build/nguồn) |
   | 📚 Tài liệu | Ngữ nghĩa theo tài liệu chính thức của dự án/thư viện |
   | ✅ Đối chiếu source | Đã kiểm chứng trong mã nguồn gốc (ClamAV hoặc repo này) |
   | 🛠️ ClamGuard | Phần đã hiện thực trong repo — trỏ tới file/class |

4. **Code block** luôn khai báo ngôn ngữ: ```text cho sample record, ```csharp cho C#,
   ```bash cho shell. Không dùng code block không có ngôn ngữ cho code thật.
5. **Bảng**: dùng GFM table; cột số canh phải; đơn vị ghi trong tiêu đề cột.
6. **Liên kết**: link tương đối giữa tài liệu trong thư mục; link tuyệt đối cho tài liệu ngoài.
7. **Tên file**: `snake_case.md`, mô tả nội dung (tiền tố `project-` cho tài liệu kiến trúc),
   không dùng khoảng trắng.
8. **Cập nhật**: khi một tài liệu được thay thế bởi bản gộp/mới hơn, ghi rõ trạng thái
   trong bảng danh mục ở file này; bản cũ bị xoá thay vì giữ song song.

## Đóng góp nhanh

```bash
# Build + chạy toàn bộ test trước khi commit tài liệu kèm code
dotnet build ClamGuard.Net.sln -c Debug
dotnet run --project tests/ClamGuard.Tests -c Debug --no-build
```
