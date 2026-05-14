# Threat Model - Lab 6 AES-CBC Socket

## Thông tin nhóm

- Thành viên 1: Phạm Thế Đức - MSSV: 1871020147
- Thành viên 2: TODO_MEMBER_2 - MSSV: TODO_MEMBER_2_ID

## Assets

Các tài sản cần bảo vệ trong hệ thống:
- **Plaintext**: bản tin gốc cần giữ bí mật khi truyền qua mạng.
- **AES key và IV**: nếu lộ, kẻ tấn công có thể giải mã toàn bộ ciphertext bắt được.
- **Ciphertext**: nếu bị sửa đổi, Receiver có thể nhận được dữ liệu sai mà không biết.
- **File đầu vào / đầu ra**: chứa nội dung nhạy cảm, cần bảo vệ trên hệ thống file.
- **File log**: có thể chứa key và IV dưới dạng hex, là điểm rò rỉ thông tin nghiêm trọng.

## Attacker model

Kẻ tấn công được giả định là có khả năng:
- **Passive eavesdropping**: nghe lén toàn bộ traffic trên mạng LAN (ví dụ dùng Wireshark hoặc ARP spoofing).
- **Active man-in-the-middle**: bắt và sửa đổi packet trên đường truyền trước khi chuyển tiếp.
- **Replay attack**: ghi lại packet hợp lệ và gửi lại sau đó để Receiver xử lý bản tin cũ.
- **Local access**: đọc file log trên máy Sender hoặc Receiver nếu có quyền truy cập hệ thống file.

Kẻ tấn công **không** có khả năng bẻ khóa AES-128/256 bằng brute force.

## Threats

**T1 - Key disclosure (Lộ khóa)**: Key và IV được gửi plaintext qua KEY_PORT. Kẻ nghe lén mạng có thể capture đầy đủ key packet, sau đó dùng key/IV đó để giải mã ciphertext bắt được trên DATA_PORT. Toàn bộ tính bảo mật của AES bị vô hiệu hóa.

**T2 - Ciphertext tampering (Sửa đổi ciphertext)**: Kẻ tấn công MITM có thể sửa một byte trong ciphertext trên DATA_PORT. AES-CBC không có MAC nên Receiver không phát hiện được sự sửa đổi; dữ liệu giải mã sẽ bị hỏng một phần hoặc lỗi padding, nhưng không có cảnh báo xác thực rõ ràng.

**T3 - Replay attack (Tấn công phát lại)**: Kẻ tấn công ghi lại cả key packet và data packet từ một phiên hợp lệ, sau đó gửi lại. Receiver sẽ giải mã thành công và xử lý bản tin cũ như thể là mới, vì hệ thống không có timestamp, nonce hay sequence number.

**T4 - Log leakage (Rò rỉ log)**: Nếu `SENDER_LOG_FILE` được cấu hình, file log ghi rõ key và IV dưới dạng hex. Ai đọc được file log có thể giải mã lại toàn bộ ciphertext đã capture.

**T5 - No sender authentication (Không xác thực Sender)**: Receiver chấp nhận kết nối từ bất kỳ client nào đến KEY_PORT và DATA_PORT. Kẻ tấn công có thể giả mạo Sender, gửi key/IV và ciphertext giả.

## Mitigations

**M1 - Dùng TLS cho kênh khóa**: Thay vì gửi key/IV plaintext, sử dụng TLS mutual authentication để trao đổi khóa an toàn, ngăn eavesdropping và MITM.

**M2 - Dùng AES-GCM thay AES-CBC**: AES-GCM kết hợp mã hóa và xác thực (AEAD), phát hiện được mọi sự sửa đổi ciphertext, giải quyết T2.

**M3 - Thêm nonce/timestamp chống replay**: Đưa timestamp hoặc nonce vào plaintext trước khi mã hóa; Receiver kiểm tra và từ chối packet quá cũ hoặc đã xử lý, giải quyết T3.

**M4 - Không ghi key vào log thật**: Trong môi trường production, log chỉ ghi metadata (port, độ dài, thời gian), không bao giờ ghi key/IV dưới bất kỳ dạng nào, giải quyết T4.

**M5 - Xác thực Sender**: Dùng certificate hoặc pre-shared token để Receiver xác minh danh tính Sender trước khi xử lý bất kỳ dữ liệu nào, giải quyết T5.

## Residual risks

Ngay cả khi áp dụng M1-M5, hệ thống vẫn còn rủi ro:
- **Key management**: Nếu private key TLS của Sender bị lộ, toàn bộ bảo mật sụp đổ. Cần có quy trình quản lý vòng đời khóa (rotation, revocation).
- **Implementation bugs**: Các lỗi như padding oracle, timing attack trên unpad, hay buffer overflow trong recv_exact vẫn có thể bị khai thác dù dùng giao thức đúng.
- **Denial of Service**: Hệ thống hiện tại không có giới hạn kích thước length header, kẻ tấn công có thể gửi length header với giá trị rất lớn khiến Receiver cố gắng cấp phát bộ nhớ lớn.
