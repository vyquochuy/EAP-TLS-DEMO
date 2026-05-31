# Phần 2: Mật mã học, Chứng chỉ số X.509 và các Thuật toán liên quan

Tài liệu này phân tích sâu sắc các nguyên lý mật mã học được áp dụng trong dự án, bao gồm cấu trúc chứng chỉ **X.509**, thuật toán toán học **RSA**, cơ chế đệm an toàn mật mã **RSA-OAEP**, và hàm băm bảo mật **SHA-256**.

---

## 1. Chứng chỉ số X.509 và Chuỗi tin cậy (Chain of Trust)

### 1.1. Cấu trúc Chứng chỉ số X.509
**X.509** là một tiêu chuẩn kỹ thuật của ITU-T định nghĩa định dạng cho chứng chỉ khóa công khai (Public Key Certificates). Một chứng chỉ số X.509 liên kết một danh tính (như cá nhân, máy chủ hoặc tổ chức) với một khóa công khai cụ thể bằng cách sử dụng chữ ký số của một bên thứ ba đáng tin cậy gọi là **Certificate Authority (CA)**.

Cấu trúc tiêu chuẩn của một chứng chỉ X.509 v3 bao gồm các trường thông tin quan trọng:

```text
+-------------------------------------------------------+
| Version (Phiên bản chứng chỉ - thông thường là v3)   |
| Serial Number (Số sê-ri độc nhất do CA cấp)           |
| Signature Algorithm (Thuật toán ký - e.g., sha256RSA)|
| Issuer (Tên đơn vị cấp phát chứng chỉ - CA)          |
| Validity (Thời hạn hiệu lực: Not Before & Not After) |
| Subject (Tên chủ sở hữu chứng chỉ - e.g., Client/Server)|
| Subject Public Key Info (Khóa công khai & Thuật toán)|
| Extensions (Các phần mở rộng mở rộng tính năng)       |
|   - Basic Constraints (Xác định cert có phải CA không)|
|   - Key Usage (Mục đích sử dụng: Ký, Mã hóa...)       |
| Signature (Chữ ký số của Issuer phủ lên toàn cert)    |
+-------------------------------------------------------+
```

### 1.2. Cơ chế xác thực chuỗi chứng chỉ (Certificate Chain Validation)
Trong EAP-TLS, khi một bên nhận được chứng chỉ từ đối phương (Peer nhận từ Server, Server nhận từ Peer), nó sẽ tiến hành xác thực theo các bước mật mã học nghiêm ngặt:

1.  **Xác minh tính toàn vẹn (Integrity Verification)**:
    *   Trích xuất chữ ký số (Signature) đính kèm ở cuối chứng chỉ.
    *   Sử dụng **Khóa công khai** của Issuer (ở đây là CA gốc) để giải mã chữ ký, thu được mã băm (Hash) gốc của chứng chỉ.
    *   Tự tính toán lại mã băm (Hash) của chứng chỉ hiện tại bằng thuật toán chỉ định (SHA-256).
    *   So sánh mã băm tự tính toán với mã băm thu được từ chữ ký số. Nếu khớp, chứng chỉ được bảo toàn toàn vẹn, không bị chỉnh sửa.
2.  **Kiểm tra thời gian hiệu lực (Validity Check)**:
    *   Đảm bảo thời gian hiện tại nằm trong khoảng giữa `Not Before` và `Not After`.
3.  **Xác minh vai trò mở rộng (Extension Constraints)**:
    *   Chứng chỉ CA ký cấp phải có trường mở rộng `Basic Constraints` chứa giá trị `CA:TRUE` cùng quyền hạn ký chứng chỉ (`keyCertSign`).
4.  **Mô phỏng trong code**:
    *   Được thực hiện bởi hàm `verify_cert(X509* cert, X509* ca_cert)` trong `cert_utils.cpp`.
    *   Hàm sử dụng cấu trúc lưu trữ của OpenSSL `X509_STORE` và bộ ngữ cảnh xác minh `X509_STORE_CTX` để thiết lập chuỗi tin cậy và tự động hóa toàn bộ quá trình kiểm tra mật mã học trên.

---

## 2. Thuật toán Mật mã học bất đối xứng RSA

**RSA** (Rivest–Shamir–Adleman) là nền tảng của mật mã học bất đối xứng được sử dụng trong dự án để thiết lập danh tính và trao đổi khóa bí mật một cách an toàn qua kênh truyền công khai.

### 2.1. Cơ sở toán học của RSA
Nguyên lý bảo mật của RSA dựa trên bài toán nghịch đảo toán học cực khó: **Bài toán phân tích một số nguyên cực lớn thành các thừa số nguyên tố (Integer Factorization)**.

#### A. Khởi tạo khóa (Key Generation)
1.  Chọn hai số nguyên tố lớn ngẫu nhiên và bí mật $p$ và $q$.
2.  Tính tích số $n = p \times q$. Số $n$ được gọi là **Module**, độ dài bit của $n$ là độ dài khóa (trong dự án ta chọn độ dài khóa RSA là 2048 bits).
3.  Tính giá trị phi hàm Euler: $\phi(n) = (p - 1) \times (q - 1)$.
4.  Chọn một số nguyên $e$ ($1 < e < \phi(n)$) sao cho ước chung lớn nhất của $e$ và $\phi(n)$ bằng 1 ($gcd(e, \phi(n)) = 1$). Số $e$ được gọi là **Số mũ công khai (Public Exponent)**. Giá trị tiêu chuẩn thường được chọn là $e = 65537$ ($2^{16} + 1$).
5.  Tính toán số $d$ sao cho: $d \times e \equiv 1 \pmod{\phi(n)}$. Số $d$ được gọi là **Số mũ bí mật (Private Exponent)**, tính bằng thuật toán Euclid mở rộng.
6.  **Khóa công khai (Public Key)** bao gồm cặp $(e, n)$.
7.  **Khóa bí mật (Private Key)** bao gồm cặp $(d, n)$ hoặc có thể lưu trữ trực tiếp bộ các số $(p, q, d)$.

#### B. Mã hóa (Encryption)
Để mã hóa một thông điệp (bản rõ) $M$ dưới dạng một số nguyên ($M < n$), ta tính bản mã $C$ bằng công thức:
$$C \equiv M^e \pmod n$$

#### C. Giải mã (Decryption)
Để giải mã bản mã $C$ thu lại bản rõ $M$, ta tính:
$$M \equiv C^d \pmod n$$
Tính đúng đắn của phép giải mã dựa trên **Định lý nhỏ Fermat** và **Định lý thặng dư Trung Hoa**.

---

## 3. Cơ chế đệm an toàn mật mã RSA-OAEP

Nếu áp dụng trực tiếp công thức RSA thuần túy (gọi là Textbook RSA hoặc RSA không đệm), hệ thống sẽ cực kỳ không an toàn trước nhiều cuộc tấn công (do RSA có tính chất nhân nhóm: mã hóa của tích bằng tích các mã hóa). Do đó, các tiêu chuẩn như PKCS#1 bắt buộc phải sử dụng cơ chế đệm dữ liệu (Padding).

### 3.1. So sánh PKCS#1 v1.5 và RSA-OAEP

Trong các phiên bản cũ, cơ chế đệm **PKCS#1 v1.5** thường được dùng. Tuy nhiên, v1.5 dễ bị tổn thương bởi các cuộc tấn công lựa chọn bản mã thích ứng (**Adaptive Chosen-Ciphertext Attacks**), điển hình là **tấn công Bleichenbacher (Million Message Attack)** nhắm vào các máy chủ SSL/TLS để dò tìm khóa PMS.

Để khắc phục hoàn toàn điểm yếu này, chuẩn **RSA-OAEP (Optimal Asymmetric Encryption Padding)** được giới thiệu trong PKCS#1 v2.0 và được sử dụng trong dự án này thông qua OpenSSL.

### 3.2. Cấu trúc mạng Feistel trong OAEP
OAEP là một sơ đồ mã hóa đối xứng dựa trên cấu trúc mạng Feistel, sử dụng hai hàm tạo mặt nạ ngẫu nhiên (Mask Generation Functions - MGF) kết hợp với các hàm băm mật mã học (như SHA-256).

```text
                      Bản rõ M (độ dài m)
                           |
                           v
                     M đệm số 0 (độ dài padding)
                           |
                           v
    Hạt giống ngẫu nhiên r ------> [ MGF1 ]
         (độ dài k0)      |          |
              |           v          v
              |          (XOR) <--- Block dữ liệu DB
              |           |
              v           v
          [ MGF1 ] <--- MaskedDB
              |           |
              v           v
            (XOR) <-------+
              |           |
              v           v
           MaskedSeed  MaskedDB
              |           |
              +-----+-----+
                    |
                    v
            Khối đệm hoàn chỉnh EM (độ dài tương thích RSA)
```

#### Nguyên lý hoạt động của OAEP:
1.  **DB (Data Block)** được tạo ra bằng cách ghép mã băm của dữ liệu tùy chọn (L), dữ liệu bản rõ cần mã hóa (M) và một chuỗi các byte đệm `0x00` kết thúc bằng một byte `0x01`.
2.  Sinh một chuỗi byte ngẫu nhiên **Hạt giống (Seed)** ký hiệu là $r$ có độ dài $k_0$ bits.
3.  Sử dụng $MGF1$ biến đổi hạt giống $r$ thành một chuỗi có độ dài tương đương $DB$, rồi thực hiện phép toán XOR:
    $$MaskedDB = DB \oplus MGF1(r)$$
4.  Tiếp tục sử dụng $MGF1$ biến đổi $MaskedDB$ trở lại thành chuỗi độ dài $k_0$ bits, rồi XOR với hạt giống $r$:
    $$MaskedSeed = r \oplus MGF1(MaskedDB)$$
5.  Khối đệm hoàn chỉnh $EM = MaskedSeed \ || \ MaskedDB$ sau đó mới được đưa vào thuật toán lũy thừa RSA để mã hóa.

**Ý nghĩa bảo mật**: OAEP cung cấp tính năng **Bảo mật ngữ nghĩa trước các cuộc tấn công lựa chọn bản mã (Semantic Security under Chosen-Ciphertext Attack - IND-CCA2)**. Một sự thay đổi dù chỉ 1 bit trong bản mã $C$ cũng sẽ làm sai lệch hoàn toàn khối đệm khi giải mã qua cấu trúc Feistel, khiến hệ thống phát hiện ra ngay lập tức và từ chối xử lý, ngăn chặn việc kẻ tấn công lấy máy chủ làm hộp đen thử nghiệm (Oracle) để giải mã.

---

## 4. Hàm băm SHA-256 và Hàm sinh khóa (Key Derivation)

Sau khi Server giải mã thành công Pre-Master Secret (PMS), cả Peer và Server đều nắm giữ chung một chuỗi bí mật ngẫu nhiên 48 bytes này. Tuy nhiên, chuỗi này không được sử dụng trực tiếp để mã hóa kênh truyền mà phải đi qua một **Hàm sinh khóa (Key Derivation Function - KDF)**.

Trong phiên bản mô phỏng này, ta sử dụng hàm băm bảo mật **SHA-256** đóng vai trò là KDF đơn giản:
$$SessionKey = SHA256(PreMasterSecret)$$

*   **Tính chất một chiều (One-Way)**: Không thể đảo ngược từ Session Key để suy ra Pre-Master Secret gốc.
*   **Tính chất kháng va chạm (Collision Resistance)**: Cực kỳ khó để tìm ra hai giá trị PMS khác nhau có cùng một Session Key.
*   **Độ dài đầu ra cố định**: Đầu ra của SHA-256 luôn là 32 bytes (256 bits), đây là độ dài hoàn hảo để làm khóa đối xứng cho các thuật toán mã hóa mạnh như **AES-256-GCM** dùng để mã hóa toàn bộ lưu lượng mạng sau đó.
