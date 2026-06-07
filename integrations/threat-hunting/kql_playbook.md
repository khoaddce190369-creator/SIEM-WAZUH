#Windows
1. Săn lùng "Slow Brute-force" (Tấn công nhỏ giọt né Active Response)

Câu lệnh KQL:
  
    rule.groups: "authentication_failed" AND NOT rule.id: ("60204" OR "5712")

Công dụng: Lọc ra tất cả các sự kiện đăng nhập thất bại trên cả Linux và Windows, nhưng loại trừ những đợt tấn công dồn dập đã bị hệ thống tự động khóa (Rule 60204 và 5712). Giúp phát hiện những kẻ kiên nhẫn dò mật khẩu rải rác vài tiếng một lần để không làm nổ cảnh báo tự động.

2. Truy vết tài khoản có dấu hiệu bị lộ (Đăng nhập thành công bất thường)

Câu lệnh KQL:

    rule.groups: "authentication_success" AND (rule.id: "5715" OR rule.id: "60106")

Công dụng: Liệt kê toàn bộ lịch sử các phiên đăng nhập thành công qua SSH (Linux) và RDP (Windows). Chuyên viên SOC sẽ dựa vào đây để soi cột srcip, nếu thấy tài khoản Admin đăng nhập thành công từ một IP lạ hoắc thì tức là mật khẩu đã bị lộ.

3. Săn lùng "Bom nổ chậm" ẩn mình (Malware Staging via FIM)

Câu lệnh KQL:

    rule.groups: "syscheck" AND syscheck.event: "added" AND syscheck.path: (*.exe OR *.sh OR *.php OR *.bat)

Công dụng: Sử dụng tính năng giám sát file (FIM) để tìm kiếm mọi file thực thi nguy hiểm vừa được tạo mới trong hệ thống. Hacker thường tải sẵn các file này lên các thư mục tạm (như /tmp hoặc Downloads) nhưng chưa kích hoạt chạy, câu lệnh này sẽ lôi chúng ra trước khi chúng kịp phá hoại.

4. Phát hiện nội gián leo thang đặc quyền (Privilege Escalation)

Câu lệnh KQL:

    rule.groups: ("sudo" OR "privilege_escalation") AND NOT data.srcuser: ("ubuntu-admin" OR "window-admin" OR "wazuh-admin")

Công dụng: Theo dõi các hành vi lạm dụng quyền hạn. Câu lệnh này sử dụng hàm NOT để loại bỏ các tài khoản quản trị hợp lệ của đội ngũ quản trị. Bất kỳ log nào xuất hiện ở đây đều cho thấy một tài khoản người dùng thường (hoặc tài khoản của ứng dụng web) đang cố tình chạy quyền tối cao.

5. Phát hiện hành vi xóa log xóa dấu vết (Defense Evasion)

Câu lệnh KQL:

    rule.id: "60114" OR rule.description: "Event log cleared"

Công dụng: Bắt quả tang ngay lập tức khi kẻ tấn công cố tình chạy lệnh xóa sạch Event Log trên Windows nhằm xóa dấu vết đột nhập, khiến các điều tra viên không thể truy tìm nguyên nhân sự cố.

6. Quét sâu hành vi PowerShell tải mã độc từ Internet

Câu lệnh KQL:

    data.win.eventdata.commandLine: (*downloadstring* OR *downloadfile* OR *-enc* OR *-encodedcommand*)

Công dụng: Quét sâu vào chi tiết các dòng lệnh chạy trên máy Windows. Lọc ra các tiến trình PowerShell đang tìm cách ẩn mình (mã hóa lệnh -enc) hoặc đang kích hoạt lệnh tải trực tiếp mã độc từ một đường dẫn URL bên ngoài Internet về máy ảo.

7. Rà soát các cuộc tấn công dò quét ứng dụng Web

Câu lệnh KQL:

    rule.groups: "web" AND rule.level >= 7 AND rule.description: (*sql* OR *xss* OR *injection* OR *exploit*)

Công dụng: Gom toàn bộ các log liên quan đến máy chủ Web, lọc ra các hành vi chọc ngoáy lỗ hổng nguy hiểm (như SQL Injection, Cross-Site Scripting - XSS) có mức độ nghiêm trọng từ Level 7 trở lên để phân tích nguồn gốc tấn công.

#Linux

8. Săn lùng hành vi cấy Backdoor bằng khóa SSH (SSH Key Persistence)

Câu lệnh KQL:

    rule.groups: "syscheck" AND syscheck.path: *authorized_keys* AND syscheck.event: ("added" OR "modified")

Công dụng: Đây là đòn hiểm nhất của hacker trên Linux! Sau khi vào được máy, chúng sẽ lén thêm Public Key của chúng vào file ~/.ssh/authorized_keys. Từ đó về sau, chúng có thể đăng nhập vào máy ông bất cứ lúc nào mà không cần biết mật khẩu, kể cả khi ông đã đổi pass. Câu lệnh này dùng FIM để "bắt sống" hành vi chỉnh sửa file nhạy cảm này.

9. Truy vết đăng nhập thẳng bằng quyền ROOT (Direct Root Login)

Câu lệnh KQL:

    rule.groups: "sshd" AND rule.id: "5715" AND data.dstuser: "root"

Công dụng: Trong chuẩn bảo mật (Best Practice), không ai được phép SSH thẳng bằng tài khoản root cả (phải dùng user thường rồi mới sudo). Nếu câu lệnh này lôi ra được log nào, chứng tỏ hệ thống của ông đang mở cửa hớ hênh cho tài khoản root, hoặc ai đó đã bẻ khóa thành công tài khoản này.

10. Phát hiện hành vi phi tang dấu vết dòng lệnh (Clear Bash History)

Câu lệnh KQL:

    rule.groups: ("syslog" OR "audit") AND rule.description: (*history* OR *cleared* OR *deleted*) AND rule.level >= 5

Công dụng: Giống như Windows có hành vi xóa Event Log, trên Linux hacker sẽ gõ lệnh history -c hoặc xóa file .bash_history trước khi thoát ra để đội SOC không biết chúng đã gõ lệnh gì. Log này nổ ra là 100% có kẻ đang muốn che giấu tung tích.

11. Săn lùng mã độc chạy ngầm định kỳ (Crontab Persistence)

Câu lệnh KQL:

    rule.groups: "syslog" AND rule.description: (*cron* OR *crontab*) AND rule.level >= 5

Công dụng: Kẻ tấn công thường lén cài một lệnh tải mã độc hoặc đào coin vào Crontab (bộ lập lịch của Linux) để cứ 5 phút nó lại tự động chạy lại một lần, đảm bảo mã độc sống dai nhách kể cả khi ông khởi động lại server.
