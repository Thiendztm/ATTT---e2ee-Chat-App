# BÁO CÁO CHUYÊN ĐỀ: XÂY DỰNG ỨNG DỤNG CHAT MÃ HÓA BẰNG DIFFIE-HELLMAN VÀ AES

## MỤC LỤC
- LỜI MỞ ĐẦU
	- 1. Lý do chọn đề tài
	- 2. Đối tượng, phạm vi nghiên cứu
	- 3. Mục tiêu nghiên cứu
	- 4. Phương pháp nghiên cứu
- CHƯƠNG 1: TỔNG QUAN VỀ AES
	- 1.1. Khái niệm và đặc điểm AES
	- 1.2. Sự ra đời và quá trình tiêu chuẩn hóa AES
- CHƯƠNG 2: MÔ TẢ THUẬT TOÁN AES
	- 2.1. Phân biệt AES và Rijndael
	- 2.2. Biểu diễn dữ liệu trong AES
	- 2.3. Các bước biến đổi trong một vòng AES
	- 2.4. Cấu trúc tổng quát các vòng mã hóa
- CHƯƠNG 3: ĐỘ AN TOÀN, ƯU NHƯỢC ĐIỂM VÀ ỨNG DỤNG
	- 3.1. Độ an toàn của AES
	- 3.2. Ưu, nhược điểm của mã hóa đối xứng
	- 3.3. Phạm vi sử dụng và liên hệ với bài toán chat an toàn
- KẾT LUẬN
- TÀI LIỆU THAM KHẢO

## LỜI MỞ ĐẦU

### 1. Lý do chọn đề tài
Trong bối cảnh chuyển đổi số, nhu cầu trao đổi thông tin qua ứng dụng nhắn tin ngày càng phổ biến, kéo theo rủi ro rò rỉ dữ liệu cá nhân và nội dung liên lạc. Các hệ thống chat thông thường có thể bị lộ dữ liệu nếu không có cơ chế mã hóa phù hợp, đặc biệt khi thông tin đi qua môi trường mạng mở.

Vì vậy, đề tài "xây dựng ứng dụng chat mã hóa bằng kỹ thuật Diffie-Hellman và mã hóa AES" được lựa chọn nhằm giải quyết trực tiếp bài toán bảo mật đầu cuối. Trong đó, Diffie-Hellman hỗ trợ thỏa thuận khóa phiên an toàn, còn AES đảm nhiệm mã hóa nội dung tin nhắn với hiệu năng cao. Đây là hướng tiếp cận vừa có ý nghĩa học thuật, vừa có giá trị ứng dụng thực tiễn.

### 2. Đối tượng, phạm vi nghiên cứu
- Đối tượng nghiên cứu: mô hình bảo mật cho ứng dụng chat sử dụng kết hợp Diffie-Hellman và AES.
- Phạm vi nghiên cứu:
	- Cơ sở lý thuyết của AES và Diffie-Hellman.
	- Cách tích hợp hai kỹ thuật này vào luồng gửi/nhận tin nhắn.
	- Đánh giá vai trò của từng thành phần trong mô hình mã hóa đầu cuối.
- Giới hạn đề tài:
	- Tập trung vào bảo mật nội dung tin nhắn và thỏa thuận khóa phiên.
	- Chưa đi sâu vào các bài toán mở rộng như lưu trữ tin nhắn lâu dài, nhóm chat lớn, hoặc hạ tầng triển khai phân tán quy mô lớn.

### 3. Mục tiêu nghiên cứu
- Trình bày cơ sở lý thuyết của hai thành phần chính: Diffie-Hellman và AES.
- Xây dựng mô hình ứng dụng chat có mã hóa đầu cuối ở mức phù hợp với đề tài môn học.
- Làm rõ vai trò của Diffie-Hellman trong việc tạo shared secret và vai trò của AES trong mã hóa/giải mã nội dung tin nhắn.
- Mô tả luồng hoạt động thực tế của hệ thống và phân tích mức độ an toàn đạt được.

### 4. Phương pháp nghiên cứu
- Phương pháp tổng hợp tài liệu: tham khảo tài liệu giảng viên, tài liệu chuẩn hóa mật mã và tài liệu kỹ thuật liên quan đến ứng dụng chat bảo mật.
- Phương pháp phân tích mô hình: phân tách hệ thống thành các lớp chức năng (thỏa thuận khóa, mã hóa dữ liệu, truyền nhận tin nhắn).
- Phương pháp xây dựng và kiểm thử: hiện thực ứng dụng chat, chạy thử các tình huống gửi/nhận tin để quan sát plaintext, ciphertext và khả năng giải mã ở hai đầu.
- Phương pháp đánh giá: đối chiếu kết quả triển khai với mục tiêu bảo mật ban đầu để rút ra kết luận và hướng cải tiến.

## CHƯƠNG 1: TỔNG QUAN VỀ AES

### 1.1. Khái niệm và đặc điểm AES
AES là thuật toán mã hóa khối theo mô hình mã hóa đối xứng, nghĩa là cùng một khóa bí mật được dùng cho cả mã hóa và giải mã.

Các thông số chính:
- Kích thước khối cố định: 128 bit.
- Độ dài khóa: 128 bit, 192 bit, 256 bit.
- Số vòng tương ứng: 10, 12, 14.

AES được thiết kế để:
- Thay thế DES do hạn chế về an toàn và hiệu năng.
- Tăng khả năng triển khai hiệu quả trên cả phần mềm và phần cứng.
- Đáp ứng yêu cầu bảo mật trong các hệ thống dân sự và chính phủ.

### 1.2. Sự ra đời và quá trình tiêu chuẩn hóa AES
Từ cuối thập niên 1980 đến đầu thập niên 1990, cộng đồng mật mã bắt đầu tìm giải pháp thay thế DES. Nhiều thuật toán được đề xuất như RC5, Blowfish, IDEA, NewDES, SAFER, FEAL.

Sau quá trình tuyển chọn quốc tế kéo dài khoảng 5 năm, năm 2001 NIST chính thức chọn Rijndael làm chuẩn AES. Thuật toán này do Joan Daemen và Vincent Rijmen thiết kế. Trong vòng chung kết còn có RC6, Serpent, MARS và Twofish.

Việc tiêu chuẩn hóa AES có ý nghĩa lớn:
- Tạo chuẩn mã hóa hiện đại thay cho DES.
- Được công khai và đánh giá sâu rộng bởi cộng đồng khoa học.
- Trở thành nền tảng cho nhiều giải pháp bảo mật ngày nay.

## CHƯƠNG 2: MÔ TẢ THUẬT TOÁN AES

### 2.1. Phân biệt AES và Rijndael
Hai tên AES và Rijndael thường được dùng thay thế nhau, nhưng không hoàn toàn giống nhau:
- Rijndael cho phép độ dài khối và khóa là bội số của 32 bit trong khoảng 128-256 bit.
- AES chỉ dùng khối 128 bit và khóa 128/192/256 bit.

Từ góc nhìn tiêu chuẩn hóa, có thể hiểu ngắn gọn như sau:
- Rijndael là thiết kế gốc mang tính tổng quát.
- AES là cấu hình chuẩn hóa của Rijndael do NIST lựa chọn.

Điểm cần lưu ý trong báo cáo:
- Khi mô tả kỹ thuật học thuật, nên phân biệt rõ hai khái niệm này.
- Khi nói về ứng dụng thực tế hiện nay, cụm từ AES thường đủ để chỉ chuẩn đang dùng.

### 2.2. Biểu diễn dữ liệu trong AES
AES xử lý dữ liệu theo ma trận trạng thái 4x4 byte (state). Mỗi vòng biến đổi tác động lên state để tăng tính rối và tính khuếch tán.

#### 2.2.1. Cấu trúc khối dữ liệu đầu vào
AES là mã hóa khối (block cipher), do đó dữ liệu đầu vào được chia thành các khối 128 bit. Mỗi khối được ánh xạ vào ma trận state 4x4 byte để phục vụ các phép biến đổi vòng.

Ý nghĩa thực tiễn của việc dùng khối 128 bit:
- Giúp chuẩn hóa quá trình xử lý dữ liệu.
- Dễ tối ưu trên phần cứng và phần mềm.
- Tạo cân bằng giữa hiệu năng và mức độ an toàn.

#### 2.2.2. Khái niệm state trong AES
State là cấu trúc trung gian quan trọng nhất trong thuật toán. Mọi phép biến đổi như thế byte, dịch hàng, trộn cột đều diễn ra trên state.

Vai trò của state:
- Là nơi kết hợp ảnh hưởng của dữ liệu gốc và khóa con.
- Tạo nền tảng cho tính khuếch tán: thay đổi 1 byte đầu vào có thể làm thay đổi nhiều byte đầu ra.
- Tăng khả năng chống phân tích thống kê bản mã.

#### 2.2.3. Khóa chính và khóa con
Từ khóa chính (key), thuật toán sinh ra dãy khóa con (round keys) thông qua quá trình mở rộng khóa. Mỗi vòng sử dụng một khóa con tương ứng để thực hiện AddRoundKey.

Tầm quan trọng của khóa con:
- Nếu chỉ dùng một khóa cố định cho mọi vòng, mức độ an toàn giảm đáng kể.
- Việc thay đổi khóa con theo vòng làm tăng độ khó cho các tấn công suy luận.
- Đây là thành phần then chốt giúp AES có cấu trúc chặt chẽ về mật mã học.

### 2.3. Các bước biến đổi trong một vòng AES
Trong mỗi vòng mã hóa, AES thực hiện các bước:
1. AddRoundKey: XOR state với khóa con.
2. SubBytes: thay thế phi tuyến từng byte qua bảng S-box.
3. ShiftRows: dịch vòng các hàng của state.
4. MixColumns: biến đổi tuyến tính theo từng cột.

Lưu ý: ở vòng cuối, bước MixColumns không được áp dụng.

#### 2.3.1. Bước AddRoundKey
Đây là bước kết hợp trực tiếp khóa vào dữ liệu bằng phép XOR theo từng byte tương ứng.

Đặc điểm:
- Phép XOR có tính khả nghịch, thuận tiện cho mã hóa và giải mã.
- Mọi vòng đều có AddRoundKey, thể hiện vai trò trung tâm của khóa.
- Nếu không biết đúng khóa con, việc đảo ngược các biến đổi tiếp theo là không khả thi trong thực tế.

#### 2.3.2. Bước SubBytes
SubBytes thay từng byte trong state bằng một giá trị khác theo S-box. Đây là phép biến đổi phi tuyến quan trọng nhất trong AES.

Ý nghĩa bảo mật:
- Tạo tính phi tuyến để chống các tấn công tuyến tính và vi sai.
- Giảm khả năng dự đoán tương quan giữa plaintext, ciphertext và khóa.
- Kết hợp cùng các bước còn lại để tăng độ rối của bản mã.

#### 2.3.3. Bước ShiftRows
ShiftRows dịch vòng các hàng trong state với số bước khác nhau, từ đó phá vỡ tính cục bộ theo cột.

Mục tiêu:
- Phân tán ảnh hưởng của SubBytes sang vị trí mới.
- Tăng hiệu quả khuếch tán khi kết hợp với MixColumns.
- Tránh việc các byte luôn ở cùng cột qua nhiều vòng xử lý.

#### 2.3.4. Bước MixColumns
MixColumns thực hiện biến đổi tuyến tính theo cột trong trường hữu hạn, làm trộn dữ liệu trong từng cột của state.

Ý nghĩa:
- Tăng tính khuếch tán mạnh mẽ giữa các byte trong cùng cột.
- Khi đi qua nhiều vòng, ảnh hưởng lan rộng toàn khối 128 bit.
- Ở vòng cuối bỏ MixColumns để duy trì thiết kế cân bằng giữa mã hóa và giải mã.

#### 2.3.5. Tính liên kết giữa bốn bước
Bốn bước trong mỗi vòng không tách rời mà tạo thành chuỗi bảo mật thống nhất:
- AddRoundKey đưa yếu tố khóa vào hệ thống.
- SubBytes tạo phi tuyến.
- ShiftRows và MixColumns tạo khuếch tán không gian dữ liệu.

Sự phối hợp này là lý do cốt lõi khiến AES vừa hiệu quả vừa khó bị phá bằng các phương pháp phân tích cổ điển.

### 2.4. Cấu trúc tổng quát các vòng mã hóa
- Bắt đầu bằng AddRoundKey ban đầu.
- Lặp nhiều vòng chuẩn gồm SubBytes, ShiftRows, MixColumns, AddRoundKey.
- Vòng cuối chỉ gồm SubBytes, ShiftRows, AddRoundKey.

#### 2.4.1. Số vòng theo độ dài khóa
- AES-128: 10 vòng.
- AES-192: 12 vòng.
- AES-256: 14 vòng.

Độ dài khóa càng lớn, số vòng càng nhiều, mức độ bảo vệ lý thuyết càng cao nhưng chi phí tính toán cũng tăng.

#### 2.4.2. Trình tự mã hóa điển hình
Một khối dữ liệu đi qua chuỗi xử lý sau:
1. Khởi tạo state từ plaintext.
2. AddRoundKey ban đầu.
3. Các vòng giữa (đầy đủ 4 bước).
4. Vòng cuối (không MixColumns).
5. Thu được ciphertext.

Trình tự này cho thấy AES không chỉ là một phép biến đổi đơn lẻ mà là quá trình lặp có cấu trúc nhằm tăng dần độ rối của dữ liệu.

#### 2.4.3. Ghi chú về chế độ hoạt động
AES chỉ là thuật toán mã hóa khối cốt lõi. Trong thực tế, AES cần được sử dụng kèm chế độ vận hành như GCM, CBC, CTR...

Đối với bài toán chat an toàn, chế độ GCM đặc biệt phù hợp vì:
- Cung cấp tính bí mật của nội dung.
- Hỗ trợ kiểm tra toàn vẹn qua thẻ xác thực (authentication tag).
- Phù hợp cho môi trường truyền tin theo gói.

## CHƯƠNG 3: ĐỘ AN TOÀN, ƯU NHƯỢC ĐIỂM VÀ ỨNG DỤNG

### 3.1. Độ an toàn của AES
AES hiện vẫn được xem là an toàn cao trong đa số bối cảnh ứng dụng thực tế nếu triển khai đúng cách.

Các điểm chính:
- Với độ dài khóa 128/192/256 bit, AES có không gian khóa rất lớn.
- Theo công bố của Chính phủ Hoa Kỳ (2003), AES có thể dùng để bảo vệ thông tin mật; mức cao hơn yêu cầu khóa 192 hoặc 256 bit theo chính sách phù hợp.
- Tấn công thực tế thường gặp là tấn công kênh bên (side-channel), tức nhắm vào triển khai thay vì phá trực tiếp cấu trúc AES chuẩn.

#### 3.1.1. Không gian khóa và khả năng chống vét cạn
Không gian khóa của AES rất lớn, khiến tấn công vét cạn (brute force) không khả thi trong thực tế hiện nay với hạ tầng tính toán thông thường.

Nhận xét:
- AES-128 đã đủ mạnh cho đa số ứng dụng dân sự.
- AES-256 thường được ưu tiên trong các hệ thống yêu cầu biên an toàn cao hơn.

#### 3.1.2. Tấn công lý thuyết và tấn công thực tế
Nhiều công bố học thuật tập trung vào phiên bản giảm số vòng hoặc các mô hình giả định đặc biệt. Điều này không đồng nghĩa AES chuẩn đã bị phá trong vận hành thực tế.

Điểm cần phân biệt:
- Tấn công lý thuyết: có ý nghĩa nghiên cứu, đánh giá biên an toàn.
- Tấn công thực tế: phụ thuộc lớn vào triển khai, cấu hình và môi trường vận hành.

#### 3.1.3. Rủi ro từ triển khai
Ngay cả khi thuật toán mạnh, hệ thống vẫn có thể bị tấn công nếu triển khai không đúng:
- Quản lý khóa yếu.
- Tái sử dụng nonce/IV sai nguyên tắc.
- Lộ thông tin qua thời gian xử lý hoặc tài nguyên phần cứng.

Vì vậy, bảo mật AES trong ứng dụng luôn là bài toán cả thuật toán lẫn kỹ thuật triển khai.

### 3.2. Ưu, nhược điểm của mã hóa đối xứng
Ưu điểm:
- Tốc độ mã hóa và giải mã nhanh.
- Hiệu năng cao với dữ liệu lớn.
- Dễ triển khai trong nhiều ứng dụng thực tiễn.

Nhược điểm:
- Bài toán phân phối khóa bí mật là hạn chế lớn nhất.
- Nếu khóa bị lộ trong quá trình trao đổi, dữ liệu mã hóa mất ý nghĩa bảo vệ.

#### 3.2.1. Phân tích ưu điểm theo góc nhìn hệ thống
Từ góc nhìn thiết kế hệ thống, mã hóa đối xứng có các điểm mạnh nổi bật:
- Độ trễ thấp, phù hợp truyền dữ liệu thời gian thực.
- Tiêu tốn tài nguyên tính toán thấp hơn nhiều so với mã hóa bất đối xứng.
- Dễ tích hợp vào cả ứng dụng web, thiết bị di động và hệ thống nhúng.

#### 3.2.2. Phân tích nhược điểm theo góc nhìn vận hành
Hạn chế lớn nhất vẫn là vấn đề vòng đời khóa:
- Sinh khóa an toàn.
- Phân phối khóa an toàn.
- Lưu trữ và thay đổi khóa định kỳ.

Nếu một trong các bước trên bị sai, lợi ích bảo mật của mã hóa đối xứng suy giảm mạnh.

#### 3.2.3. Khi nào nên ưu tiên AES
AES phù hợp khi:
- Cần mã hóa lượng dữ liệu lớn với hiệu năng cao.
- Hệ thống đã có kênh trao đổi khóa đáng tin cậy.
- Cần tiêu chuẩn mật mã phổ biến, được hỗ trợ rộng rãi bởi thư viện chuẩn.

### 3.3. Phạm vi sử dụng và liên hệ với bài toán chat an toàn
Phạm vi sử dụng:
- Phù hợp cho mã hóa dữ liệu lưu trữ nội bộ (single user).
- Phù hợp cho hệ thống đã có kênh trao đổi khóa an toàn.
- Với môi trường nhiều đối tác, cần cơ chế bổ sung để chia sẻ khóa an toàn.

Liên hệ bài toán chat an toàn:
- AES dùng để mã hóa plaintext thành ciphertext trước khi gửi.
- Phía nhận dùng khóa tương ứng để giải mã ciphertext.
- AES xử lý tốt phần mã hóa dữ liệu; còn trao đổi khóa cần cơ chế riêng để bảo đảm tính an toàn đầu cuối.

#### 3.3.1. Vai trò của AES trong mô hình E2EE
Trong hệ thống chat đầu cuối, AES thường giữ vai trò mã hóa nội dung phiên liên lạc. Server chỉ chuyển tiếp bản mã mà không đọc được nội dung gốc.

Điều này giúp:
- Giảm rủi ro lộ dữ liệu trên đường truyền.
- Hạn chế tác động khi server bị quan sát hoặc ghi log lưu lượng.
- Đảm bảo chỉ hai đầu liên lạc có thể giải mã tin nhắn.

#### 3.3.2. Liên hệ trực tiếp với bài làm
Trong bài làm, khi người dùng nhập plaintext (ví dụ "alo"), dữ liệu được mã hóa thành ciphertext trước khi gửi đi. Bản mã thường ở dạng chuỗi hex hoặc base64, không có ý nghĩa ngôn ngữ tự nhiên.

Đây là biểu hiện đúng của mã hóa tốt:
- Cùng một plaintext có thể cho ra ciphertext khác nhau nếu nonce khác nhau.
- Người ngoài chỉ thấy dữ liệu ngẫu nhiên, không thể suy diễn nội dung.

#### 3.3.3. Giới hạn của phần AES trong hệ thống chat
AES giải quyết tốt phần mã hóa dữ liệu, nhưng chưa tự giải quyết bài toán thỏa thuận khóa ban đầu giữa hai bên.

Do đó, trong hệ thống hoàn chỉnh cần:
- Một cơ chế trao đổi khóa an toàn.
- Cơ chế xác thực danh tính khóa công khai.
- Quy trình làm mới khóa theo phiên hoặc theo thời gian.

## KẾT LUẬN
Từ các phân tích trên có thể thấy AES là chuẩn mã hóa đối xứng hiện đại, có nền tảng lý thuyết vững chắc và giá trị ứng dụng cao. Cấu trúc gồm nhiều vòng biến đổi với các bước AddRoundKey, SubBytes, ShiftRows, MixColumns giúp thuật toán đạt được mức độ bảo mật mạnh trong khi vẫn đảm bảo hiệu năng.

Về thực tiễn, AES đặc biệt phù hợp cho các hệ thống cần mã hóa dữ liệu nhanh, liên tục và quy mô lớn. Tuy nhiên, hiệu quả bảo mật cuối cùng không chỉ phụ thuộc vào thuật toán mà còn phụ thuộc lớn vào quản lý khóa, cách triển khai và cơ chế vận hành đi kèm.

Đối với bài toán chat an toàn, AES đảm nhiệm tốt vai trò bảo mật nội dung tin nhắn. Để tạo thành hệ thống đầu cuối hoàn chỉnh, cần kết hợp thêm cơ chế thỏa thuận khóa và xác thực phù hợp. Đây cũng là hướng mở rộng hợp lý cho phần tiếp theo của đề tài.

## TÀI LIỆU THAM KHẢO
- Tài liệu bài giảng của giảng viên về AES.
- NIST, FIPS 197: Advanced Encryption Standard (AES).