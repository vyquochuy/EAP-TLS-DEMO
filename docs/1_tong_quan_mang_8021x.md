# Phần 1: Tổng quan Kiến trúc Mạng 802.1X và Giao thức EAP-TLS

Tài liệu này phân tích sâu lý thuyết mạng về chuẩn kiểm soát truy cập cổng mạng **IEEE 802.1X**, kiến trúc xác thực **AAA**, cơ chế đóng gói **EAP/EAPoL**, và chi tiết luồng trao đổi thông điệp của giao thức **EAP-TLS** (RFC 5216).

---

## 1. Kiến trúc Kiểm soát Truy cập Cổng mạng IEEE 802.1X

**IEEE 802.1X** là một chuẩn bảo mật của IEEE dùng để kiểm soát truy cập mạng dựa trên cổng (Port-based Network Access Control). Chuẩn này ngăn chặn các thiết bị không được phép kết nối vào mạng LAN hoặc WLAN doanh nghiệp trước khi chúng được xác thực thành công.

Kiến trúc 802.1X định nghĩa **3 vai trò thực thể tách biệt**:

```text
  +------------------+          +------------------------+          +-----------------------+
  |    Supplicant    | <======> |      Authenticator     | <======> | Authentication Server |
  | (Thiết bị Client)|  EAPoL   | (Access Point / Switch)|  RADIUS  |    (RADIUS Server)    |
  +------------------+          +------------------------+          +-----------------------+
```

### 1.1. Supplicant (Thiết bị yêu cầu xác thực)
*   **Định nghĩa**: Là phần mềm hoặc thực thể phần cứng chạy trên thiết bị đầu cuối của người dùng (như laptop, smartphone, thiết bị IoT) muốn truy cập vào tài nguyên mạng.
*   **Nhiệm vụ**: Phản hồi các yêu cầu từ Authenticator bằng thông tin đăng nhập hợp lệ (trong EAP-TLS là Chứng chỉ số X.509 cá nhân và khóa riêng đi kèm).
*   **Mô phỏng trong code**: Được biểu diễn bởi lớp `EAPPeer` (`peer.h` / `peer.cpp`).

### 1.2. Authenticator (Thiết bị kiểm soát truy cập)
*   **Định nghĩa**: Thiết bị mạng biên trung gian điều phối quá trình kiểm soát cổng truy cập vật lý hoặc logic (thường là **L2 Switch** hoặc **Wireless Access Point - WAP**).
*   **Nhiệm vụ**:
    *   Giữ cổng ở trạng thái **Khóa (Unauthorized)** trước khi xác thực: Chỉ cho phép các gói tin điều khiển xác thực (EAPoL) đi qua, chặn toàn bộ dữ liệu người dùng (IP traffic).
    *   Đóng vai trò làm bộ lọc/chuyển tiếp (Proxy): Nhận thông điệp EAPoL từ Supplicant, bóc tách và đóng gói lại vào giao thức của mạng xương sống (thường là RADIUS qua UDP/IP) để chuyển tới Authentication Server, và ngược lại.
    *   Mở cổng sang trạng thái **Mở (Authorized)** sau khi nhận tín hiệu thành công (`EAP_SUCCESS`) từ Server.
*   **Mô phỏng trong code**: Được biểu diễn bởi lớp `EAPAuthenticator` (`authenticator.h` / `authenticator.cpp`).

### 1.3. Authentication Server (Máy chủ xác thực)
*   **Định nghĩa**: Máy chủ trung tâm lưu trữ thông tin nhận dạng và quản lý chính sách truy cập (thường là **RADIUS Server** như FreeRADIUS, Cisco ISE, Microsoft NPS).
*   **Nhiệm vụ**:
    *   Tiếp nhận thông điệp từ Authenticator.
    *   Kiểm tra tính hợp lệ của thông tin xác thực của Supplicant (thực hiện kiểm tra tính toàn vẹn chữ ký, chuỗi tin cậy chứng chỉ, chứng chỉ hết hạn hay bị thu hồi).
    *   Ra quyết định chấp nhận (`EAP_SUCCESS`) hoặc từ chối (`EAP_FAILURE`) kết nối mạng và gửi kết quả về cho Authenticator.
*   **Mô phỏng trong code**: Được biểu diễn bởi lớp `AuthenticationServer` (`auth_server.h` / `auth_server.cpp`).

---

## 2. Giao thức EAP và Đóng gói EAPoL (EAP over LAN)

### 2.1. EAP (Extensible Authentication Protocol)
**EAP** (định nghĩa trong **RFC 3748**) là một khung giao thức (Framework) xác thực linh hoạt, không chỉ định một phương thức xác thực cụ thể mà cho phép tích hợp nhiều thuật toán bảo mật khác nhau (như mật khẩu tĩnh, OTP, thẻ thông minh, hoặc chứng chỉ số).

Một gói tin EAP chuẩn bao gồm cấu trúc tiêu đề cơ bản:
```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Code      |  Identifier   |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Type       |  Type-Data...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
```
*   **Code (1 byte)**: Xác định loại gói tin EAP:
    *   `1` - Request (Yêu cầu thông tin từ Server)
    *   `2` - Response (Phản hồi từ Client)
    *   `3` - Success (Xác thực thành công)
    *   `4` - Failure (Xác thực thất bại)
*   **Identifier (1 byte)**: Số định danh tuần tự dùng để khớp một gói tin *Response* với gói tin *Request* tương ứng.
*   **Length (2 bytes)**: Tổng chiều dài của toàn bộ gói tin EAP (bao gồm Code, Identifier, Length và Data).
*   **Type (1 byte)**: Xuất hiện trong gói Request/Response để chỉ định phương thức EAP cụ thể:
    *   `1` - Identity (Yêu cầu định danh)
    *   `13` - **EAP-TLS** (Giao thức bảo mật lớp truyền tải - đối tượng mô phỏng chính)
    *   `21` - EAP-TTLS (Tunneled TLS)
    *   `25` - PEAP (Protected EAP)

### 2.2. EAPoL (EAP over LAN)
EAP ban đầu được thiết kế để truyền tải trên lớp liên kết dữ liệu PPP (Point-to-Point Protocol). Để áp dụng EAP vào mạng cục bộ dây (Ethernet - 802.3) hoặc không dây (Wi-Fi - 802.11), chuẩn IEEE 802.1X giới thiệu cơ chế đóng gói **EAPoL** (EAP over LAN) ở tầng liên kết dữ liệu (Data Link Layer - Layer 2).

Gói tin EAPoL bao bọc gói tin EAP bên trong trường dữ liệu của nó trước khi truyền qua mạng:
```text
+-------------------+----------------+-----------------+-----------------+
| Ethernet Header   | EAPoL Header   | EAP Header      | EAP Data        |
| (L2 Mac Address)  | (Type, Length) | (Code, Type...) | (Certificates..) |
+-------------------+----------------+-----------------+-----------------+
```
*   **EAPoL Type**:
    *   `0x00`: EAP-Packet (Chứa gói tin EAP bên trong).
    *   `0x01`: EAPOL-Start (Supplicant chủ động gửi để thông báo muốn bắt đầu xác thực cổng).
    *   `0x02`: EAPOL-Logoff (Client thông báo ngắt kết nối để đóng cổng).

---

## 3. Chi tiết Giao thức EAP-TLS (RFC 5216)

**EAP-TLS** là sự kết hợp giữa khung giao thức xác thực EAP và giao thức bảo mật lớp truyền tải **TLS** (Transport Layer Security). Đây là một trong những cơ chế xác thực an toàn nhất hiện nay vì nó bắt buộc **Xác thực hai chiều (Mutual Authentication)**.

### 3.1. Tại sao EAP-TLS vượt trội hơn các phương thức khác?

| Đặc tính | EAP-TLS | PEAP-MSCHAPv2 | EAP-TTLS |
| :--- | :--- | :--- | :--- |
| **Xác thực phía Server** | Yêu cầu Chứng chỉ số | Yêu cầu Chứng chỉ số | Yêu cầu Chứng chỉ số |
| **Xác thực phía Client** | **Yêu cầu Chứng chỉ số (X.509)** | Tên đăng nhập & Mật khẩu | Tên đăng nhập & Mật khẩu / Token |
| **Mức độ an toàn** | **Cực cao** (Chống giả mạo và nghe lén hoàn hảo) | Trung bình khá (Dễ bị tấn công từ điển ngoại tuyến nếu mật khẩu yếu) | Cao (Lớp đường hầm bảo vệ thông tin đăng nhập) |
| **Độ phức tạp triển khai** | Cao (Cần hạ tầng khóa công khai PKI để cấp phát cert cho client) | Trung bình (Chỉ cần chứng chỉ ở phía Server) | Trung bình (Chỉ cần chứng chỉ ở phía Server) |

### 3.2. Tiến trình bắt tay EAP-TLS chi tiết

Luồng trao đổi thông điệp EAP-TLS bao gồm ba giai đoạn chính:

#### Giai đoạn 1: Thiết lập EAP & Định danh (Identity)
1.  **EAPOL-Start**: Supplicant phát tín hiệu muốn kết nối.
2.  **EAP-Request/Identity**: Authenticator yêu cầu Client gửi định danh.
3.  **EAP-Response/Identity**: Client gửi định danh của mình (ví dụ: `Peer`).

#### Giai đoạn 2: Thiết lập Kênh truyền TLS (TLS Handshake)
4.  **EAP-Request/TLS-Start**: Máy chủ xác thực yêu cầu bắt đầu phiên bắt tay TLS.
5.  **EAP-Response/TLS (ClientHello + Client Certificate)**: 
    *   Client khởi động bắt tay TLS, gửi cấu hình bảo mật được hỗ trợ (Cipher Suites, TLS version).
    *   Đồng thời, Client đính kèm **Chứng chỉ số cá nhân (Client Certificate)** để tự xác thực mình với Server.
6.  **EAP-Request/TLS (ServerHello + Server Certificate)**:
    *   Server lựa chọn Cipher Suite phù hợp, sinh khóa ngẫu nhiên của Server.
    *   Server gửi lại **Chứng chỉ số của Server (Server Certificate)** để Client kiểm tra danh tính của Server.

#### Giai đoạn 3: Trao đổi Khóa và Kết thúc
7.  **EAP-Response/TLS (Encrypted Pre-Master Secret)**:
    *   Client xác minh thành công chứng chỉ của Server dựa trên chứng chỉ CA tin cậy.
    *   Client sinh ngẫu nhiên một tiền khóa bí mật **Pre-Master Secret** gồm 48 bytes.
    *   Client sử dụng **Khóa công khai** trích xuất từ chứng chỉ Server để mã hóa PMS này (RSA-OAEP) và gửi về Server.
    *   Cả Client và Server đều sử dụng PMS để sinh ra **Session Key** (Khóa phiên bảo mật phiên truyền thông).
8.  **EAP-Success**: Server giải mã thành công PMS bằng khóa riêng của mình, xác thực toàn vẹn thông điệp, xác nhận trùng khớp khóa phiên và gửi lệnh chấp thuận kết nối mạng tới Authenticator. Authenticator mở cổng vật lý/logic cho phép Client truy cập.
