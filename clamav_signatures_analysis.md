# Tổng Hợp Chi Tiết Về Các Định Dạng Chữ Ký ClamAV

Tài liệu này tổng hợp và phân tích chi tiết các định dạng chữ ký của ClamAV dựa trên các tài liệu chính thức từ docs.clamav.net.

## 1. Tổng Quan Về Chữ Ký (Signatures)

ClamAV sử dụng nhiều loại chữ ký khác nhau để phát hiện phần mềm độc hại, được phân loại chủ yếu dựa trên phần mở rộng của tệp cơ sở dữ liệu.
*   **Ràng buộc tên chữ ký:** Tên của một virus/chữ ký chỉ được chứa các ký tự chữ, số (alphanumeric), dấu gạch ngang (`-`), dấu chấm (`.`), và dấu gạch dưới (`_`). Không cho phép khoảng trắng, dấu nháy đơn, dấu nháy kép, hoặc các ký tự đặc biệt khác.
*   **Các loại chính:** Chữ ký dựa trên nội dung (Body-based), chữ ký băm (Hash-based), và các loại nâng cao khác như YARA, Bytecode, Phishing.

## 2. Chữ Ký Dựa Trên Nội Dung (Body Signature Format)

ClamAV lưu trữ các mẫu (patterns) dưới định dạng hexa (hexadecimal).
*   Ví dụ: `ClamAV-Test-Signature=58544f4f`
*   **Wildcards (Ký tự đại diện):**
    *   `??`: Khớp với 1 byte bất kỳ.
    *   `a?`: Khớp với 1 byte có phần cao (high nibble) là `a`.
    *   `?b`: Khớp với 1 byte có phần thấp (low nibble) là `b`.
    *   `*`: Khớp với số lượng byte bất kỳ.
    *   `{n}`: Khớp chính xác với `n` byte.
    *   `{-n}`: Khớp với tối đa `n` byte.
    *   `{n-}`: Khớp với tối thiểu `n` byte.
    *   `{n-m}`: Khớp từ `n` đến `m` byte.
*   **Character Classes (Lớp ký tự):** Cho phép thay thế (alternatives), ví dụ `(61|62|63)` khớp với `a`, `b`, hoặc `c`. Tương tự như regex nhưng dưới dạng hex. Có thể bỏ qua các ký tự theo khoảng (range) ví dụ `[20-7f]`.

## 3. Chữ Ký Mở Rộng (Extended Signatures - `.ndb`)

Định dạng `.ndb` cung cấp khả năng tìm kiếm nâng cao với offset.
*   **Cú pháp:** `TênVirus:TargetType:Offset:HexSignature[:MinFL:[MaxFL]]`
    *   `TargetType`: Chỉ định loại tệp (0=Bất kỳ, 1=PE, 2=OLE2, 3=HTML, 6=ELF, v.v.).
    *   `Offset`: Có thể là giá trị tuyệt đối, EOF (End Of File) `EOF-n`, EP (Entry Point) `EP+n`, hoặc regex (ví dụ `a,b` - bắt đầu tìm từ a, khoảng không gian tối đa b).
    *   `MinFL`/`MaxFL`: Functionality Level (tùy chọn) - giới hạn phiên bản engine ClamAV áp dụng chữ ký này.

## 4. Chữ Ký Logic (Logical Signatures - `.ldb`)

Cho phép kết hợp nhiều sub-signatures bằng các toán tử logic để tạo ra các luật phức tạp hơn.
*   **Cú pháp:** `TênVirus;TargetDescriptionBlock;LogicalExpression;SubSig0;SubSig1;...`
    *   `TargetDescriptionBlock`: Cung cấp thông tin loại tệp, offset, hoặc thông tin chi tiết (ví dụ PE section). Nếu `TargetType` là 0, khối này có thể là `Target:0` (bất kỳ file nào). Định dạng chi tiết là `Target:X`, `Engine:X-Y`, `FileSize:X-Y`, v.v.
    *   `LogicalExpression`: Biểu thức logic sử dụng các chỉ số của SubSig (0, 1, 2...) kết hợp với các toán tử `&` (AND), `|` (OR), `=` (bằng), `>` (lớn hơn). Ví dụ: `(0&1&2)|3` (nếu khớp sig0, sig1, sig2 HOẶC khớp sig3).
    *   `SubSig`: Chữ ký hex hoặc có thể có format đặc biệt với offset cụ thể.

## 5. Chữ Ký Băm (Hash-based Signatures)

Chữ ký băm nhanh chóng nhận dạng các tệp tĩnh. Cần thận trọng vì chỉ cần thay đổi 1 byte, chữ ký sẽ không khớp.
*   **MD5 (.hdb):** `HashString:FileSize:MalwareName`
*   **SHA1 & SHA256 (.hsb):** `HashString:FileSize:MalwareName[:MinFL]` (ClamAV phân biệt qua độ dài chuỗi hash).
*   **Hash của PE Section (.mdb / .msb):** Khớp hash của từng section trong file PE (EXE/DLL). Cú pháp: `PESectionSize:PESectionHash:MalwareName`
*   **Hash của PE Import Table (.imp):** Cú pháp: `PEImportTableHash:PEImportTableSize:MalwareName`
*   Có thể sử dụng `*` cho `FileSize` nếu không biết kích thước, nhưng phải có `MinFL` >= 73 (ví dụ `Hash:*:Name:73`).

## 6. Chữ Ký Phishing (.pdb, .wdb, .gdb)

Phát hiện các liên kết lừa đảo giả mạo domain. Hiển thị qua cảnh báo `Heuristics.Phishing.Email.SpoofedDomain`.
*   **PDB (Domain list):** Danh sách các domain mục tiêu để theo dõi. (Cú pháp: `R:Regex` hoặc `H:Hostname`).
*   **WDB (Allow list):** Danh sách cho phép, tránh false positives. (Cú pháp: `X:RealURL:DisplayedURL`, `Y:RealURL`, `M:RealHostname:DisplayedHostname`).
*   **GDB:** Hash của Google Safe Browsing (ví dụ `S:` cho malware, `S2:` cho phishing).
*   Hỗ trợ cờ (Flags) để tuỳ chỉnh kiểu check cho từng domain. URL sẽ được tách thành `RealURL` (nơi thực sự đi tới) và `DisplayedURL` (chuỗi hiển thị). Regex được cung cấp để so khớp concatenation của cả hai.

## 7. Quy Tắc YARA (.yar hoặc .yara)

ClamAV hỗ trợ quy tắc YARA với một số giới hạn:
*   Không hỗ trợ modules (keyword `import`).
*   Không hỗ trợ biến toàn cục (`global`) hoặc biến ngoài (`contains`, `matches`).
*   Tối đa 64 chuỗi mỗi quy tắc và phải có ít nhất 1 chuỗi hợp lệ.
*   Hỗ trợ phủ định (Negation) trong Hex String: `~HH` (trừ byte HH), `~H?`, `~?H`. Khác với toán tử bitwise NOT `~` trong conditions.
*   Do ClamAV giải nén và bình thường hoá (normalize) HTML/ASCII, YARA rules cũng sẽ được scan trên dữ liệu đã bình thường hoá.

## 8. Chữ Ký Bytecode (.cbc)

Là các đoạn mã C được biên dịch ra bytecode, cung cấp khả năng khớp phức tạp nhất.
*   Cho phép can thiệp vào các giai đoạn giải nén và phân tích tĩnh của file.
*   Tương tác qua API của ClamAV để kiểm tra nội dung và trigger cảnh báo mã độc.
*   Một chữ ký bytecode có thể tạo ra nhiều loại thông báo khác nhau tuỳ thuộc vào phân tích.

## 9. Chữ Ký Container Metadata (.cdb)

Kiểm tra tệp tin dựa trên metadata của chính container chứa nó (ví dụ file ZIP, RAR, TAR).
*   **Cú pháp:** `VirusName:ContainerType:ContainerSize:FileNameREGEX:FileSizeInContainer:FileSizeReal:IsEncrypted:FilePos:Res1:Res2[:MinFL[:MaxFL]]`
*   Giúp nhắm tới chính xác tệp thực thi bên trong một file nén với điều kiện kích thước, tên, hay CRC cụ thể.

## 10. Chữ Ký Authenticode (Chứng chỉ tin cậy và bị thu hồi - .crb)

Kiểm tra chứng chỉ của các file PE được ký số.
*   **Cú pháp:** `Name;Trusted;Subject;Serial;Pubkey;Exponent;CodeSign;TimeSign;CertSign;NotBefore;Comment[;minFL[;maxFL]]`
*   `Trusted`: 1 là tin cậy, 0 là bị thu hồi. 
*   Cho phép liệt kê các chứng chỉ cụ thể để từ chối các phần mềm độc hại có ký số hợp lệ hoặc bỏ qua các phần mềm từ nhà cung cấp hợp pháp.

## 11. Cấu Hình Động (Dynamic Configuration - .cfg)

DCONF cho phép thay đổi bật/tắt các tính năng cấu hình của ClamAV engine thông qua các bản cập nhật database.
*   Thường được đưa vào tệp `daily.cfg`.
*   **Cú pháp:** `Category:Flags:StartFlevel:EndFlevel`
*   Được sử dụng khi ClamAV cần nhanh chóng tắt một tính năng bị lỗi ở một phiên bản Engine (Flevel) nhất định mà không cần cập nhật toàn bộ phần mềm.

## 12. Phân Tích Thư Mục Cache Của ClamGuard

Dựa trên việc kiểm tra thực tế thư mục `C:\ProgramData\ClamGuard\cache\daily_28146_f035c4fd10fd33f9fadd5905acb78b7e`, đây là nơi lưu trữ các tệp cơ sở dữ liệu đã được giải nén của bộ chữ ký ClamAV (có khả năng là phiên bản "daily" được tải về). 

Danh sách các phần mở rộng và loại tệp thực tế được tìm thấy tương ứng với các tài liệu đã phân tích:
*   **`.ldb` / `.ldu`**: Cơ sở dữ liệu chữ ký logic (Logical Signatures) và bản cập nhật của chúng (`.ldu` - logical database update). Tệp `daily.ldb` có kích thước rất lớn (~76MB), cho thấy phần lớn các quy tắc phức tạp được viết dưới dạng này.
*   **`.ndb` / `.ndu`**: Cơ sở dữ liệu chữ ký mở rộng (Extended Signatures) dựa trên hex.
*   **`.hdb` / `.hsb`**: Cơ sở dữ liệu chữ ký băm (MD5 và SHA1/SHA256). Tệp `daily.hsb` (~3.8MB) chiếm một lượng lớn.
*   **`.mdb` / `.msb`**: Cơ sở dữ liệu băm của các PE section.
*   **`.hdu` / `.hsu` / `.ndu` / `.mdu` / `.msu`**: Các tệp tin cập nhật (update) bổ sung tương ứng cho các định dạng CSDL gốc.
*   **`.cdb`**: Chữ ký dựa trên Container Metadata.
*   **`.cfg`**: Tệp cấu hình động (Dynamic Configuration).
*   **`.crb`**: Cơ sở dữ liệu chứng chỉ tin cậy/bị thu hồi (Trusted/Revoked Certificates).
*   **`.pdb` / `.wdb`**: Cơ sở dữ liệu phát hiện và cho phép Phishing (Phishing / Allow lists).
*   **`.fp` / `.sfp`**: Các tệp tin "False Positive", dùng để loại trừ các tệp băm an toàn khỏi việc bị nhận dạng nhầm.
*   **`.ign` / `.ign2`**: Danh sách các chữ ký bị bỏ qua (Ignored signatures) để tắt nhanh các chữ ký gây nhận dạng nhầm trước khi cập nhật CSDL đầy đủ.
*   **`.ftm`**: Cơ sở dữ liệu File Type Magic, dùng để nhận dạng chính xác loại tệp dựa trên file header thay vì chỉ dựa vào phần mở rộng (extension).
*   **`.info`**: Tệp thông tin mô tả chi tiết về phiên bản và metadata của cơ sở dữ liệu (version, ngày cập nhật, v.v.).
*   **`.idb`**: Thường là tệp chứa Icon Database, dùng để so khớp các biểu tượng (icon) khả nghi thường được mã độc giả mạo của các file thực thi.

Thư mục này cho thấy ứng dụng đang sử dụng bộ cơ sở dữ liệu chữ ký chuẩn của ClamAV, áp dụng rất phong phú tất cả các cơ chế phân tích từ khớp chuỗi hex, logic kết hợp, đến băm các phần tử của mã độc.

---
*Tài liệu này được tổng hợp để cung cấp một cái nhìn tổng quát và chi tiết nhằm giúp viết và hiểu các chữ ký ClamAV.*
