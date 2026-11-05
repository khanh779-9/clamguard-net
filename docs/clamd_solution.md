# Giải pháp Load/Đọc Database cho ClamGuard-Net

> Tài liệu thiết kế chi tiết: tối ưu RAM, tốc độ và độ chính xác khi load/đọc DB signature,
> tham khảo từ project **MalwardAV-main** (VDEB: MMF + Bloom Filter + Shard Index).

---

## Mục lục

1. [Tổng quan vấn đề](#1-tổng-quan-vấn-đề)
2. [Phân biệt 2 bài toán DB](#2-phân-biệt-2-bài-toán-db)
3. [Hiện trạng của clamguard-net](#3-hiện-trạng-của-clamguard-net)
4. [Bài học từ MalwardAV-main (VDEB)](#4-bài-học-từ-malwardav-main-vdeb)
5. [Giải pháp A — Hash Lookup DB (MMF + Bloom + Shard)](#5-giải-pháp-a--hash-lookup-database)
6. [Giải pháp B — Signature DB Pattern Matching](#6-giải-pháp-b--signature-database)
7. [Định dạng file_binary_cache đề xuất](#7-định-dạng-file-binary-cache-đề-xuất)
8. [Tham số cấu hình khuyến nghị](#8-tham-số-cấu-hình-khuyến-nghi)
9. [Kỳ vọng hiệu năng](#9-kỳ-vọng-hiệu-năng)
10. [Lộ trình triển khai](#10-lộ-trình-triển-khai)
11. [Rủi ro & lưu ý](#11-rủi-ro--lưu-ý)

---

## 1. Tổng quan vấn đề

Mục tiêu: engine khi load / đọc DB phải đạt đồng thời 4 tiêu chí:

| Tiêu chí | Ý nghĩa |
|---|---|
| **Chính xác** | Không tăng false-negative lẫn false-positive so với hiện tại |
| **Tối ưu** | Ít I/O thừa, ít CPU thừa, ít bước lặp lại cùng 1 dữ liệu |
| **Mượt** | Load chạy nền không khóa UI; không bị spike RAM khiến GC dừng dài (GC pause) |
| **Nhẹ RAM** | Resident memory thấp khi đang load và sau khi load xong |

Điểm mấu chốt của tài liệu: **không có một cơ chế "thần thánh" duy nhất**.
Phải tách theo *dạng dữ liệu*, vì mỗi dạng có đặc điểm truy vấn khác nhau:

- **Byte-pattern** (NDB/LDB/DBM...) → cấu trúc phù hợp là **Aho-Corasick/ECA**, không phải bloom.
- **Hash lookup** (MD5/SHA phải match chính xác 1 đoạn) → cấu trúc phù hợp là
  **Bloom Filter + Shard Index + Binary Search** — chính là thiết kế VDEB của MalwardAV.

---

## 2. Phân biệt 2 bài toán DB

### 2.1. Đặt tên cho rõ

Xác định thuật ngữ (đáp ứng câu hỏi "load DB và đọc DB có phải là một?"):

- **Đọc DB (read)** = thao tác I/O thuần: lấy bytes từ file lên RAM.
- **Load DB (load)** = đọc + xác minh (verify/chỉnh hash CMS/MD5) + giải nén (gzip của CVD)
  + parse từng dòng chữ ký + lọc theo PUA/kiểm duyệt + **compile** thành cấu trúc tra cứu
  (Aho-Corasick, ECA index, hash tables...) + đưa vào trạng thái "sẵn sàng quét".

→ **Load DB bao gồm Đọc DB**, nhưng đọc chỉ là 1 bước nhỏ. Tối ưu "đọc"
(MMF, streaming) chỉ tối ưu 1 phần; phần "compile" và "giữ gìn sau compile" mới là chỗ
ngốn RAM lớn nhất.

### 2.2. Hai dạng access pattern

| | **Signature pattern DB** (`.ndb`, `.ldb`, `.dbm`, hex sig trong `.cvd`) | **Hash/whitelist DB** (`.hsb`, `.fp`, `.sfp`, whitelist, verdict-cache) |
|---|---|---|
| Truy vấn | "Có chuỗi byte nào trong file khớp pattern nào không?" | "Hash (MD5/SHA-256) của file/payload có nằm trong danh sách không?" |
| Kết quả | Tìm *tất cả* match khả dĩ (dẫn lọc) | Binary: có/không |
| Cấu trúc dữ liệu tối ưu | Trie/Aho-Corasick (đúng như hiện tại) | Bloom + shard + binary search / hash table |
| Bloom filter | **Không có tác dụng** (từ khóa không phải hash, không "một-nhiều hashable") | **Hoàn hảo** — chặn 99.9% file sạch trước khi chạm DB |
| MMF khi load | Ít lợi (vẫn phải parse mọi dòng rồi compile) | **Lợi hoàn toàn** — không cần load toàn bộ DB vào RAM |
| MMF khi scan | Đã dùng cho file lớn (giữ nguyên) | Đã dùng |

---

## 3. Hiện trạng của clamguard-net

### 3.1. Những gì đang làm đúng (giữ nguyên)

| Nơi | Nội dung | Đánh giá |
|---|---|---|
| `SignatureParser.cs` | `File.ReadLines` lazy — không nạp cả file | ✅ Đúng |
| `DatabaseLoader.Specialized.cs` | `File.ReadLines` cho phần lớn `.ftm/.dconf/.wdb...` | ✅ Đúng |
| `CvdReader.cs` | GZip-stream giải nén từng khối, không buffer cả file | ✅ Đúng |
| `ScannerEngine.cs` L313–324 | File lớn → `MemoryMappedFile.CreateFromFile` + `CreateViewStream`, chunk-stream match | ✅ Đúng hướng |
| `AhoCorasick.cs` | Sparse trie (edge-list) chuyển sang frozen contiguous arrays + **DFA-flatten 8192 state đầu (≈8 MiB)** | ✅ Đúng hướng, cấu trúc tốt cho RAM |
| `DatabaseManager.cs` | Compile lại khi DB thay đổi, background load (`loading_db`) | ✅ Đúng |

### 3.2. Chưa tối ưu (cần làm)

1. **ReadAllBytes/ReadAllText/ReadAllLines/ToArray còn nhiều**: 
   - `DatabaseVerifier.cs` L161: `File.ReadAllBytes(path)` (tải cả `.cvd` lên RAM chỉ để verify).
   - `DatabaseLoader.Specialized.cs` L430: `.ToArray()` nạp hết các dòng catalog/info (file nhỏ — chấp nhận được, nhưng nên gọi người xem xét).
   - `YaraEngine.cs`, `ClamBcEngine.cs`: `File.ReadAllText` — file nhỏ, chấp nhận.
2. **Chưa có compiled-state cache**: `CacheDirectory` chỉ dùng để cache container-extract
   (`DatabaseLoader.cs` L152–159). **Restart = compile lại từ đầu** — vừa lâu, vừa phải trải qua phase trung gian ngốn RAM gấp 2–3 lần sản phẩm cuối.
3. **Signature giữ dưới dạng object/`string` phân mảnh**: sau compile, `SignatureDatabase`
   vẫn giữ objects; phần lớn chỉ cần lúc compile, nên release.
5. **Bloom filter không tồn tại** (grep toàn codebase = 0) — cần bổ sung cho các hash DB.

---

## 4. Bài học từ MalwardAV-main (VDEB)

Thành phần VDḂ (file `EngineSDK\Malward.Engine\Vdeb\VdebReader.cs`):

```
┌─────────────────────── VDEB file (updated on-disk layout) ──────────────────────┐
│ 0x00 HEADER 256 bytes                                                          │
│      magic = "VDEB"(0x42454456), version, flags(GZIP|COMPACT),                 │
│      bloom_offset, bloom_size, index_offset, index_count(256 shard),           │
│      total_entries, created_ts, last_ts, malware_count, clean_count,           │
│      compact_prefix                                                            │
│ 0x100 BLOOM FILTER  region  (raw bit-array, no compression; mapped via MMF)     │
│ 0x??? INDEX           region  (256 × 32 bytes; shard key = 2 hex đầu)          │
│ 0x??? DATA            region  (per-shard GZip stream; load-on-demand)          │
└────────────────────────────────────────────────────────────────────────────────┘
```

Điểm mạnh thiết kế (đã xác minh bằng code):

1. **V1 — MMF toàn file** (`VdebReader.cs` L42–44): DB download xong mount
   `MemoryMappedFile.CreateFromFile(..., MemoryMappedFileAccess.Read)`; header/bloom/index
   decompress-on-demand hoặc map-on-demand — **không bao giờ load cả DB**.
2. **V2 — Bloom filter nằm trong file** (`BloomFilter.cs`):
   - size 128 MiB bit-array, **k = 7** hàm hash, hash FNV-1a với salt `i*31` cho từng hàm k
   - nằm trực tiếp trên đĩa, truy cập via `MemoryMappedViewAccessor` → lại không tốn RAM
   - `MightContain()` chỉ cần 7 once-read-byte; page fault nhẹ
3. **V3 — Shard theo prefix 2 hex đầu** (`VdebReader.cs` L79–92):
   - key 256 shard: `00`–`ff`; tra vào đúng shard chứa hash `hh...`
   - mỗi shard gzip riêng, LRU shard cache capacity 16 (`ShardCache.cs`)
   - chỉ decompress shard truy vấn; shard tự hủy LRU
4. **V4 — Verify chính xác cuối cùng**:
   - shard COMPACT = prefix n-byte được **sort** → binary search (`BinarySearchPrefixes`)
   - shard FULL = scan tuần tự payload đúng hash type + verify binary equal → phát hiện tuyệt đối
5. **V5 — Bloom false-positive không gây sai**: bloom MISS → chắc chắn không có trong DB;
   bloom HIT → shard decompress + binary-search/scan xác thực. Sai chí mạng = 0, chỉ có
   false positive chi phí ~1 decompress shard (tính bằng phần triệu).

> **Kết luận:** VDEB là mẫu chuẩn cho **hash-lookup database** trong AV.
> ClamAV chính nói CI cũng khởi tạo cơ chế tương tự cho hash-based sig (`cli_hashsearch`).

---

## 5. Giải pháp A — Hash Lookup Database

Áp dụng cho: `.hsb`/`.hsd` (file-hash DB của ClamAV), whitelist `.fp`/`.sfp`,
verdict-cache (lưu kết quả scan file theo hash), sau này VPS/cloud lookup cache.

### 5.1. Kiến trúc tổng thể

```
                    ┌───────────────────────────────┐
   .hsb / .fp       │  build-time (ONCE per DB)     │  →  clamguard.hdb (custom)
   ───────────────► │  parse → shard by prefix →    │     • header 256B
                    │  sort each shard → gzip each  │     • bloom bit-array
                    │  → build bloom → write file   │     • shard index
                    └───────────────────────────────┘     • gzip shards
                                                                                  scan-time
                    ┌───────────────────────────────────────────────────────────┐ ◄──
 sha256/md5 hex ──► │ FNV1a × 7 → Bloom.MightContain? ──MISS──► null (không có)  │
                    │                       │                                   │
                    │                      HIT                                  │
                    │                       ▼                                   │
                    │ shard key = hex[0..1] → index[256 entry] → shard offset    │
                    │                       ▼                                   │
                    │ LRU cache hit? ── yes ──► binary search (prefix) /         │
                    │                       │   linear verify (full)            │
                    │                        no                                 │
                    │                       ▼                                   │
                    │ MMF view → read comp bytes → gunzip → cache LRU → search   │
                    └───────────────────────────────────────────────────────────┘
```

### 5.2. Build-time (offline, khi user cài DB / update `daily.cvd`)

Bước 1 — Parse nguồn (stream, lazy):
```csharp
foreach (var line in File.ReadLines(sourcePath))
{
    // "hash:det:name" hoặc ".fp" (hash-only); bỏ comment '#'
    var hash = ParseHexHash(line);              // MD5(16B) | SHA1(20B) | SHA256(32B)
    var detection = ParseDetectionName(line);
    bucket[(hash[0] << 4) | hash[1]].Add((hashBytes, detection));
}
```
Bước 2 — Với mỗi shard: sort entries theo hash-bytes → ghi tuần tự.
(Sort để hỗ trợ binary search mục "prefix compact").

Bước 3 — Build bloom (trước khi ghi file):
```csharp
// bit-array m bytes; k = 7; FNV-1a 32-bit + salt
long sizeBits = (long)bloomSizeBytes * 8;
foreach (var entry in allHashes)
{
    foreach (var i in ..7)
    {
        uint h = FNV_OFFSET;
        foreach (var b in entry.HashBytes) { h ^= b; h = unchecked(h * FNV_PRIME); h ^= (uint)(i * 31); }
        bits[(h % sizeBits) >> 3] |= (byte)(1 << (int)(h % 8));
    }
}
```

Bước 4 — Ghi file custom theo layout VDEB (xem §7).

### 5.3. Scan-time lookup (hot path)

```csharp
public sealed class HashDatabase : IDisposable
{
    private readonly MemoryMappedFile _mmf;
    private readonly MemoryMappedViewAccessor _bloomView;
    private readonly Dictionary<ushort, IndexEntry> _index;
    private readonly LruShardCache _cache;          // capacity 16 shards
    private readonly BloomFilter _bloom;

    public bool TryFind(string md5Hex, string sha256Hex, out string? detection)
    {
        detection = null;

        // 1. Bloom prefilter: đọc 7 bit trong bit-array mapped; MISS → dừng ngay,
        //    không decompress shard nào
        if (sha256Hex is not null && !_bloom.MightContain(sha256Hex.ToLowerInvariant())
            && (md5Hex is null || !_bloom.MightContain(md5Hex.ToLowerInvariant())))
            return false;                                  // ~99.9% file sạch đi đến đây và thay vì 0 decompress

        // 2. Shard pick
        var key = (ushort)(((HexNib(sha256Hex[0]) << 4) | HexNib(sha256Hex[1])));

        if (!_index.TryGetValue(key, out var entry)) return false;

        // 3. LRU cache / decompress shard
        var payload = _cache.GetOrLoad(key, () => DecompressShard(_mmf, entry));

        // 4. Verify final (có Bloom từng-thành-phần BẮT-TRƯỚC)
        //    - mode compact: binary search prefix(BE bytes), xác nhận 0 comparator mismatch
        //    - mode full   : linear scan payload, verify sequence-equal từng entry
        detection = SearchPayload(payload, md5Hex, sha256Hex);
        return detection is not null;
    }
}
```

Giải thích chi tiết:

1. **Bloom đứng trước** để chặn nhanh: chỉ đọc 7 byte trong bit-array mapped —
   0 decompress, 0 parse. Đẹp nhất là `MISS` → quay về ngay không tốn hơn tôi branch 7 lần.
2. **Shard theo 2 hex đầu** (256 bucket) khiến sau bloom HIT chỉ decompress 1 shard
   ID nhỏ (~25–50 KiB gunzipped, ~5–15 KiB gz). Không máy nào phải decompress cả DB.
3. **Verify cuối luôn chính xác** — bloom chỉ là prefilter nghĩa là:
   - false positive → hụt decompress shard + miss verify → không sai
   - false negative → **cấm bằng cài đặt**: mọi hash phải set bit trước build-end:
     ```csharp
     // self-check trong builder (build fail nếu có entry không set):
     foreach (var e in allHashes) Debug.Assert(_bloom.MightContain(e.HashHex));
     ```
4. **LRU shard cache** chỉ giữ `capacity` shard mới nhất (16 mặc định): scan tuần tự
   các file theo prefix không shard lại hoán xuất → decompress lại rất ít.

### 5.4. Dùng cho whitelist `.fp`/`.sfp`

Không đổi giao diện — chỉ thay đổi backing store (file `.fp` text parse thành hash-list
rồi build chung cùng format §7). Lợi ích:

- Fresh-build gây whitelist to (lớn theo update) → MMF làm snapshot RAM thấp.
- Scan check `.fp` hiện là hash-table full — chuyển thành bloom-first nếu whitelist >
  vài trăm nghìn entry.

> **Quyết định quy mô**: whitelist nhỏ (< ~200 000 entries / ~10 MB RAM) — hash-set hiện tại
> vẫn ổn; bloom/MMF chỉ có lợi khi whitelist phình to. Đừng chuyển vội nếu chưa thấy
> metric cho phép.

### 5.5. Dùng cho ScanVerdictCache

C يمكنك dùng possibilité: mở rộng `ScanVerdictCache` hiện tại (hash → verdict)
thành cùng format, tự tái-sau-bao-nhiêu-ngày. Được premium: whitelisting *.flt* nhanh —
hầu hết file OS đều clean, bloom chặn tức thì.

---

## 6. Giải pháp B — Signature Database

### 6.1. Nguyên tắc: không dùng Bloom cho signature pattern

- Pattern là byte sequence *không hash hóa được* → bloom không dự-đoán được match.
- Aho-Corasick đã prefilter tốt ngay từ build (chính bloom đó nếu lạm dụng sẽ đè RAM).
- **Chỉ giữ Aho-Corasick/ECA làm prefilter**. Việc cố ép bloom cho pattern chỉ là
  over-engineering → **loại khỏi phạm vi triển khai**.

### 6.2. Chiến lược RAM: parse → arena → release → cache

```
           phase 1                phase 2                 phase 3
   ┌──────────────────┐   ┌──────────────────────┐   ┌─────────────────────┐
   │ Streaming parse  │──►│ Build AhoCorasick /  │──►│ Serialize compiled  │
   │ (File.ReadLines, │   │ ECA index; literals  │   │ state → clamcache   │
   │  gzip stream,    │   │ vào 1 arena byte[]   │   │ (binary format §7)  │
   │  không materialize│  │ (offset/length int)  │   │                     │
   └──────────────────┘   └──────────────────────┘   └─────────────────────┘
                                                        │
        sau khi ghi cache: release cả (1)+(2)           ▼
                                               ┌─────────────────────┐
                                               │ Lần KHỞI-ĐỘNG sau:  │
                                               │ load cache bằng MMF │
                                               │ hoặc deserialize    │
                                               │ trực tiếp           │
                                               └─────────────────────┘
```

### 6.3. Arena buffer cho pattern/literal

Nguyên lý (bạn được nhắc trước): thay `List<string>`/`string[]`/`byte[][]` riêng lẻ
(mỗi object .NET có header ~16–24B, MLP fragmentation lớn) bằng **một buffer lớn duy nhất
+ `int offset/length`**:

```csharp
public sealed class SignatureArena
{
    private byte[] _data = new byte[1 << 20];       // 1 MiB cấp ước, grow ×2
    private int _count;

    public int Add(ReadOnlySpan<byte> bytes)
    {
        if (_count + bytes.Length > _data.Length) Grow(bytes.Length);
        bytes.CopyTo(_data.AsSpan(_count));
        var @ref = _count;
        _count += bytes.Length;
        return @ref;                                 // offset trong arena
    }

    public ReadOnlySpan<byte> Get(int offset, int length) => _data.AsSpan(offset, length);
}
```

Công dụng:

- NDB/DBM literal (hex-string sau decode) → lưu arena.
- `AhoCorasick` vẫn nhận `ReadOnlySpan<byte>` như hiện tại — không đổi API.
- Signature record sau compile chỉ lưu `(int arenaOffset, int len)`.

Ước lượng tiết kiệm: với main.cvd ~600 000 literals trung bình ~24B →
mảng JIT-string ≈ 600K × (24 + header 24 + alignment) ≈ **30+ MB overhead**
thành khoảng **15 MB arena thô**; giảm tới ~50% phần literal. Cùng giảm GC gen2
(fragmentation giảm cực mạnh).

### 6.4. Serde compiled state ra file cache

- Load mọi lần khởi động tránh phải compile từ đầu (giảm CPU + giảm RAM-phase).
- Đường dẫn cache: `%ProgramData%\ClamGuard\cache\compiled\` —
  tên file chứa `(databaseName, version, md5)` để MISS tự vứt khi DB update.
  Đây chính là cách ClamAV làm `.cld` (cache binary của `.cvd`).
- Serde format = §7 với các section khác tương ứng:
  header (dump-time db info, struct layout version) + frozen arrays section.
- Lần đầu load (chưa có cache): vẫn compile nhưng chạy **trong background + streamDatos**,
  sau đó ghi cache; các lần khởi động sau = load từ cache bỏ qua parse.
- **Fallback**: nếu deserialize cache lệch checksum (file cache hỏng) → tự vứt cache,
  trở về compile từ DB gốc.

### 6.5. Không dùng MMF cho compile nhưng dùng cho kho ultra-big

- Compile-phase cần *ngẫu nhiên*_prefixed writes và list-churning — MMF không giúp gì.
- Sau khi cache thành binary frozen arrays, **bước load-cache có thể dùng MMF+view**
  nếu ta làm frozen-arrays unmanaged (`NativeMemory.Alloc`/`MemoryMappedFile` pinned),
  nhưng trong .NET, các `int[]`/`byte[]` được GC-manage nên thực tế
  **deserialize trực tiếp `File.ReadAsync` → `GCHandle pinned`** thường nhanh và dự
  đoán được hơn; chỉ cân nhắc MMF khi cache quá lớn để buffer toàn bộ vào RAM.

---

## 7. Định dạng file binary cache đề xuất

Tham khảo VDEB nhưng tổng quát hóa cho cả hash-DB và compiled-cache:

```
Offset  Size  Field
─── HEADER 256 bytes ───
0x00    4     magic: 'CGV1' (0x31564743, big-endian theo ASCII)
0x04    4     format_version (uint32)
0x08    4     flags: bit0=GZIP, bit1=COMPACT(sorted-prefixed), bit2=ARENA, ...
0x0C    4     reserved (0)
0x10    8     bloom_offset (int64)
0x18    8     bloom_size   (int64)
0x20    8     index_offset (int64)
0x28    4     index_count  (uint32)                          [n = số shard/section]
0x2C    4     index_entry_size (uint32, self-documented = 32)
0x30    8     total_entries  (uint64)
0x38    8     db_version     (uint64, dùng cho cache invalidation)
0x40    16    db_md5 / content hash (16B)                    [dùng cho cache invalidation]
0x50    8     created_ts     (uint64, unix)
0x58    8     payload_crc32c (uint64; CRC32C tổng vùng DATA)  [data integrity]
0x60..0xFF    reserved (0)

─── BLOOM REGION (mapped-on Read) ───
(bloom_size bytes; raw bit-array; k=7, FNV-1a 32-bit salt = i*31)

─── INDEX REGION (n × 32 bytes self-sized) ───
+0x00   2     key/shard_key  (2 hex char đầu; uint16)
+0x02   6     reserved
+0x08   8     data_offset (int64 → tuyệt đối trong file)
+0x10   4     compressed_size   (uint32)
+0x14   4     uncompressed_size (uint32)
+0x18   4     entry_count       (uint32)
+0x1C   4     reserved

─── DATA REGION (mỗi section GZip stream) ───
- mode full:    [type(1B) | detFlag(1B) | hash(16/20/32B) | detLen(2B LE)| det(UTF8) | (4B tail)]...
                Trong đó entry được sắp theo thứ tự tăng-dần để chuẩn bị binary search
- mode compact: chuỗi các prefix n-byte (n = compact_prefix) đã sort — chỉ literal prefix
- compiled-cache: [section-tag | frozen array bytes nguyên trạng]
```

*Ghi chú: đặc tính self-documented — mọi entry có index_entry_size ghi trong header,
phiên bản sau có thể mở rộng mà không phá compat (bằng cách nâng format_version).*

---

## 8. Tham số cấu hình khuyến nghị

| Tham số | Giá trị khuyến nghị | Ghi chú |
|---|---|---|
| Bloom size | `128 MiB` (MalwardAV) | Đủ cho ~10⁷ entries @ FPR ≈ 0.02–0.05% với k=7. DB nhỏ dùng 16–32 MiB đủ |
| Bloom k (hash count) | `7` | Optimal k cho FPR target |
| Bloom hash | FNV-1a 32-bit + salt `i*31` | Nhanh, đủ chất lượng cho bloom |
| Shard count | `256` (prefix 2 hex) | Balanced: shard ~25–50 KB gunzipped |
| LRU shard cache | `16` shard | Thấp RAM; hot-file scan tuần tự cùng prefix-pattern |
| AhoCorasick dense states | `8192` (hiện trạng, ≈8 MiB) | Tăng lên `32768` nếu profile thấy cache-miss ở state sâu |
| Stream chunk size | giữ hiện trạng `Limits.StreamChunkSize` | Không đổi |
| Cache dir | `%ProgramData%\ClamGuard\cache\compiled\` | File cache tên `db_{name}_{version}_{md5}.cgc` |
| Verdict-cache TTL | 7–14 ngày | Cập nhật trước khi DB update |

---

## 9. Kỳ vọng hiệu năng

Số liệu *ước lượng lý thuyết*, dựa trên thiết kế MalwardAV (đã cài thật) + đặc tính
ClamAV database (cần chạy benchmark thật trên DB của bạn trước khi hào hứng):

| Kịch bản | Trước | Sau | Vì sao |
|---|---|---|---|
| **Scan file sạch (bloom MISS)** | tính hash → hash-set lookup (RAM phụ thuộc DB size) | tính hash → 7 byte-read của mapped bloom → dừng | 0 decompress, 0 shard, ~µs |
| **Scan file match hash (bloom HIT)** | hash-set O(1) | bloom + shard decompress + verify | Nhumea chậm hơn vài trăm µs — chấp nhận, vì chỉ chiếm ~0.01–0.05% file |
| **Load DB lần đầu** | parse + compile toàn bộ | như cũ (streaming) + ghi cache | chậm hơn tí (~5–10%) do ghi cache |
| **Khởi động lần 2+** | parse + compile lại từ 0 | deserialize cache hoặc MMF | nhanh hơn nhiều lần; RAM-phase nếu dùng arena ổn định |
| **RAM sau load (signature DB)** | nhiều object string phân mảnh | arena + release parse-objects | giảm được khoảng 30–50% phần literal/sig-structural |
| **RAM whitelist/hash DB** | hash-set toàn bộ trong RAM | MMF + LRU shard | gần như ~0 so với map; chỉ LRU (mấy trăm KB) |
| **GC pause** | gen2 lớn do object nhiều | arena là single-object | gấp vài lần ít pause |

> **Không claim**: không hứa con số cụ thể chưa đo. Cần benchmark trên main.cvd thật.

---

## 10. Lộ trình triển khai

### Phase 1 — (tiền điều kiện, bugfix nhỏ)
- [ ] Gỡ các `ReadAllBytes`/`ReadAllLines`/`ToArray` không cần thiết
  (`DatabaseVerifier.cs` L161 — verify CVD bằng stream hash thay vì bytes toàn file).

### Phase 2 — Giải pháp A (hash DB)
- [ ] Tạo `ClamGuard.Database.HashDb` module:
  `HashDbBuilder` (build từ `.hsb`/`.fp`/verdict JSON) + `HashDatabaseReader` (lookup).
- [ ] Cài BloomFilter (FNV-1a ×7, k tham số hóa), ShardCache LRU, IndexEntry read.
- [ ] Tích hợp với `ScanPipeline` ở nhánh hash-check hiện của `.fp/.sfp` + hash-sig DB.
- [ ] Unit test: bloom FPR đo thực nghiệm (cho 10⁶ random hash + 1 correct hit),
  miss-never test (những entry add phải hit 100%).
- [ ] Benchmark so sánh với hash-set hiện tại: time lookup + RAM + IO.

### Phase 3 — Giải pháp B (signature DB)
- [ ] Thêm `SignatureArena`; chuyển NDB/DBM literal sang arena (API AhoCorasick giữ nguyên).
- [ ] Sau compile release parse-stage objects (`SignatureDatabase` không giữ hết raw strings).
- [ ] Serde `CompiledSignatureSet` + `AhoCorasickMatcher` frozen arrays ra file cache (§7).
- [ ] Lần khởi động sau: load cache; tự MISS → compile lại + ghi cache mới.
- [ ] Self-check: cache CRC32C; lệch thì vứt + rebuild.
- [ ] Lần 1 chạy trên thiết bị chậm: đo cả phase (parse/build/serialize/load).

### Phase 4 — Đo + tinh chỉnh
- [ ] Benchmark A/B: load time, RAM peak, RAM steady, GC gen2 count, CPU.
- [ ] Chỉnh tham số §8 theo số liệu thật.
- [ ] Tài liệu hóa trên `docs/`.

---

## 11. Rủi ro & lưu ý

1. **Bloom false-negative**: phải tự-check build-time (§5.3 bước 4) — không tự-check
   = nguy cơ miss detection thực — chấp nhận mức RISK = 0.
2. **Định dạng custom**: file cache custom có nguy cơ phụ-hụt nếu lỗi format —
   vẫn phải MD5-verify file DB root thay đổi tự MISS/rebuild.
3. **MMF + antivirus khác**: một số AV khác quét của MapViewOfFile callback liều cần
   — đảm bảo file clamguard DB nằm trong trusted-self path để không tự-phòng-ngừa
   chính nó (clamguard-net đã có self-protection-config sẵn).
4. **File-corruption**: chạy `crc32c` section DATA (§7) để develop + release đầy đủ
   detect gây data-hazard.
5. **MemoryMappedFile trong môi trường hạn chế**: MMF yêu cầu pagefile support;
   sandbox hạn chế quyền (AppContainer) — nếu có ngữ cảnh chạy sandbox check fail-safe:
   fallback ParseStream thường.
6. **Đừng lạm dụng Bloom cho sig pattern**: mọi đề-xuất "bloom cho NDB/DBM pattern"
   phải REJECT (§6.1).
7. **Cache invalidation**: bằng `(db_version, db_md5)`. Không dùng thời gian tuyệt đối.
8. **Threading**: MMF view accessor không thread-safe — việc đọc bloom/index nên đọc qua
   accessor riêng mỗi thread, còn **LRU shard cache cần lock** (hoặc lock-free ring với
   immutable snapshot trao đổi qua `Interlocked.Exchange`).

---

## Phụ lục — So sánh ngắn với MalwardAV & ClamAV

| Cơ chế | MalwardAV (VDEB) | ClamAV chuẩn | clamguard-net sau giải pháp |
|---|---|---|---|
| Database format | `.vdeb` binary custom | `.cvd` (tar.gz text) + `.cld` (cache binary) | giữ compat ClamAV + file cache/binary riêng |
| Hash lookup | MMF + Bloom + shard + binary search | `cli_hashsearch` (hashset-trie trong RAM) | Bloom + shard + MMF (tốt hơn ClamAV chuẩn về RAM cấp độ hash DB lớn) |
| Pattern prefilter | N/A (engine hash-based) | Aho-Corasick (`cli_ac_buildtrie`) | giữ Aho-Corasick frozen + DFA dense |
| Load từ cache | N/A | `.cld` | `.cgc` (custom, tương tự `.cld`) |
| MMF dùng khi | luôn | không hằng | hash DB + file lớn Scan |

Cuối cùng — chi tiết thực hiện cần cẩn thận theo mặc định:
**đúng ở giai đoạn nào dùng giai đoạn đó**; không cơ chế nào bữa-sáng "làm mọi thứ nhanh hơn".
