# Peer Review Response - Lab 6 AES-CBC Socket

## Thông tin nhóm

- Thành viên 1: Phạm Thế Đức - MSSV: 1871020147
- Thành viên 2: Claude - MSSV: N/A

---

## Phản hồi nhận xét từ nhóm review

### Nhận xét 1: Cách xử lý padding

**Nhận xét:** Reviewer đề xuất kiểm tra thêm trường hợp padding với dữ liệu có độ dài đúng bằng bội số của 16 byte.

**Phản hồi:** Chúng tôi đồng ý và đã bổ sung test `test_pad_unpad_roundtrip` để kiểm tra padding cho nhiều độ dài dữ liệu khác nhau, bao gồm trường hợp độ dài chính xác là bội số của block size. Theo chuẩn PKCS#7, khi dữ liệu đã đủ block thì vẫn phải thêm một block padding 16 bytes, do đó hàm `pad` của chúng tôi xử lý đúng với `pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)`.

### Nhận xét 2: Bảo mật kênh khóa

**Nhận xét:** Reviewer chỉ ra rằng việc gửi key/IV plaintext qua kênh TCP không an toàn trong thực tế.

**Phản hồi:** Chúng tôi đồng ý hoàn toàn. Đây là thiết kế học tập nhằm mô phỏng luồng trao đổi khóa, không phải hệ thống thực. Trong threat model chúng tôi đã ghi rõ điểm yếu này và đề xuất dùng TLS hoặc Diffie-Hellman key exchange cho hệ thống thật. README cũng có ghi chú rõ: _"Key và IV vẫn được gửi plaintext, vì vậy thiết kế này không an toàn để dùng trong hệ thống thật"_.

### Nhận xét 3: Thiếu xác thực (authentication)

**Nhận xét:** Reviewer đề nghị bổ sung cơ chế xác thực Sender.

**Phản hồi:** Chúng tôi ghi nhận. Trong phạm vi bài lab, chúng tôi chỉ mô phỏng mã hóa AES-CBC, không triển khai xác thực. Để cải thiện, hệ thống thật nên dùng AES-GCM (kết hợp mã hóa và MAC) hoặc thêm HMAC-SHA256 cho ciphertext. Điều này đã được đề cập trong phần mitigations của threat model.

---

## Những thay đổi sau peer review

- Bổ sung docstring ngắn cho các hàm utils.
- Bổ sung test case cho padding khi dữ liệu = bội số block size.
- Cập nhật threat model để mô tả rõ hơn attack vector trên kênh khóa.
