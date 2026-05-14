# Report 1 page - Lab 6 AES-CBC Socket

## Thông tin nhóm

- Thành viên 1: Phạm Thế Đức - MSSV: 1871020147
- Thành viên 2: Claude - MSSV: N/A

## Mục tiêu

Bài lab này xây dựng hệ thống gửi và nhận dữ liệu mã hóa qua TCP socket sử dụng AES-CBC, kế thừa từ ý tưởng Lab 3 DES Socket nhưng nâng cấp lên AES và tách thành 2 kênh riêng biệt. Mục tiêu cụ thể gồm: (1) cài đặt AES-CBC với PKCS#7 padding đúng chuẩn, (2) thiết kế giao thức 2 kênh TCP tách biệt giữa kênh khóa (KEY_PORT) và kênh dữ liệu (DATA_PORT), (3) dùng length header 4 byte để truyền dữ liệu nhị phân an toàn qua socket, (4) viết test kiểm thử đầy đủ, và (5) phân tích điểm yếu bảo mật của thiết kế hiện tại.

## Phân công thực hiện

- **Thành viên 1** phụ trách: `aes_socket_utils.py` (hàm pad/unpad, encrypt/decrypt, build/parse packet), `sender.py`, test padding và test key channel.
- **Thành viên 2** phụ trách: `receiver.py`, test data channel, test wrong key, test tamper, test local sender-receiver.
- **Phần làm chung**: threat model, report, peer review response, tạo log minh chứng.

## Cách làm

**AES-CBC và PKCS#7 padding**: Sử dụng thư viện `pycryptodome`. Hàm `pad` thêm `n` bytes có giá trị `n` vào cuối plaintext (n = 1..16), đảm bảo luôn thêm ít nhất 1 byte. Hàm `unpad` kiểm tra tính hợp lệ của padding trước khi xóa.

**Giao thức key channel**: Packet gồm `[key_length: 4 bytes big-endian][key: 16/32 bytes][iv: 16 bytes]`. Sender gửi trước qua `KEY_PORT`, Receiver lắng nghe và parse để lấy key và IV.

**Giao thức data channel**: Packet gồm `[ciphertext_length: 4 bytes big-endian][ciphertext: N bytes]`. Sender gửi qua `DATA_PORT` sau khi đã gửi key.

**Hàm `recv_exact`**: Đọc đúng N byte từ TCP connection, xử lý trường hợp TCP phân mảnh dữ liệu thành nhiều segment.

**Sender**: Đọc plaintext từ env `MESSAGE`, file `INPUT_FILE`, hoặc stdin; mã hóa AES-CBC; gửi tuần tự key packet rồi data packet; ghi log nếu có `SENDER_LOG_FILE`.

**Receiver**: Lắng nghe KEY_PORT trước, nhận key/IV; sau đó lắng nghe DATA_PORT, nhận ciphertext; giải mã và in kết quả; ghi log và output file nếu được cấu hình.

## Kết quả

- Chạy thành công demo local: Sender gửi `"Xin chao FIT4012 - Lab 6 AES Socket"`, Receiver giải mã và in đúng bản tin gốc.
- Tất cả 16 test pass (padding, key channel, data channel, wrong key, tamper, integration).
- Log minh chứng được lưu tại `logs/receiver_success.log` và `logs/sender_success.log`.
- Output giải mã lưu tại `sample_output.txt`.

## Kết luận

**Bài học kỹ thuật**: AES-CBC yêu cầu padding đúng chuẩn PKCS#7, IV ngẫu nhiên mỗi phiên, và length header để truyền dữ liệu nhị phân qua TCP. TCP có thể chia nhỏ dữ liệu, nên cần `recv_exact` thay vì gọi `recv` một lần.

**Bài học bảo mật**: Mã hóa dữ liệu không đồng nghĩa với bảo mật toàn diện. Hệ thống này thiếu xác thực Sender, không toàn vẹn dữ liệu (không có MAC/HMAC), và đặc biệt kênh khóa gửi key/IV plaintext là điểm yếu chết người. Trong hệ thống thật phải dùng TLS hoặc cơ chế trao đổi khóa an toàn (Diffie-Hellman, RSA), và thay AES-CBC bằng AES-GCM để có xác thực tích hợp.
