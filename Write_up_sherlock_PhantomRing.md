## Write up sherlock PhantomRing

## mô tả

Your organization's SOC team intercepted a suspicious binary during a routine threat hunting operation on a Linux server. The file was found in /var/tmp with an unusual name and was attempting to establish outbound connections. Initial analysis suggests this could be a post-exploitation agent. Your task is to perform static analysis on the binary to identify its capabilities, extract indicators of compromise, and understand the threat actor's infrastructure.

## tool: kali , IDA pro

Sau khi giải nén file zip thu được file tên: agent

mô tả đã gợi ý file đc tìm thấy ở /var/tmp rất có thể đây là 1 file malware nên tiến hành xem file đó là gì. điểm lưu ý : not stripped chứng tỏ hacker chưa xóa thông tin debug

## task 1: What is the SHA256 hash of the malicious binary?

để biết được mã hash của file là gì ném file lên virus total


## ANS:

## 2d7b1b2178f76c26893b2a56cbf9b36700235259e76b893d53817d5b66b634a5

ngoài ra thông tin ở đây còn cho biết đây là một RAT/Backdoor sử dụng API io_uring để ẩn mình, có khả năng trinh sát hệ thống, leo thang đặc quyền và kết nối ngược về một địa chỉ C2 được hardcode là 192.168.56.1:4445

## Task2: What is the IP address hardcoded in the binary for C2 communication?

như phân tích ở trên ta biết được ip kết nối về c2

ANS: 192.168.56.1

## Task3: What port does the agent connect to on the C2 server?

cũng như phân tích ở trên

ANS: 4445

Task4: How many seconds does the agent wait before attempting to reconnect after a failed connection?

Đến đây ta dùng IDA/Hydra để phân tích file mã độc này

theo như câu hỏi liên quan đến thời gian ta nghĩ ngay tới các hàm sleep() , usleep() , nanosleep() , select() hoặc là một nhánh xủ lý lỗi của một lệnh goi

network connect()


Vào hàm main→ alt+T sleep và ta đã có được time : 0x78u đổi HEX sang DEC=120s

## ANS:120

## Task5:How many different commands does the agent support? (excluding invalid commands)

Để tìm được câu trả lời trước tiên hãy phân tích đoạn mã của hàm main

ta có thể thấy Buffer nhận dữ liệu là v13 tham số của io_uring_prep_recv được truyền

thẳng vào hàm process_cmd

tiếp theo vào hàm process_cmd để đọc. Tổng cộng có 11 hàm cmd


## ANS: 11

## Task6:What Linux kernel interface does this malware abuse to evade EDR syscall monitoring?

Nhìn lại hàm main() đa số luồng network I/O đều đi qua các hàm io_uring_* thay vì gọi socket API chuẩn trực tiếp

## ANS: io_uring

## Task7: What file does the agent read to enumerate logged-in users?

đề hỏi liên quan tới users nhìn lại vào hàm process_cmd Hàm process_cmd đóng vai trò điều phối lệnh,nhận chuỗi lệnh từ qua

io_uring_prep_recv , so sánh bằng strncmp /strcmp với tập lệnh đã định nghĩa sẵn. Khi

input khớp với chuỗi "users" , process_cmd gọi tới hàm cmd_users để thực thi logic thu thập users


Chuyển qua hàm cmd_users để xem

*ANS: /var/run/utmp*


## Task8:What directory does the agent scan when searching for SUID binaries for privilege escalation?

đề hỏi tới lệnh privesc ta sẽ vào hàm cmd_privesc để xem

## ANS: /usr/bin

## Task9:What string does the agent search for in /proc/[pid]/maps to identify security tools using eBPF?

liên quan tới lệnh killbpf → vào hàm cmd_killbpf .Agent chắc chắn có 1 vòng lặp duyệt qua các PID trong /proc , đọc file /proc/[pid]/maps của từng process, rồi dùng

strstr()


ANS: anon_inode:bpf-map

## Task10: What is the full path of the first tracing file the agent attempts to disable?

đề bài nhắc tới tracing file search thì đây là một từ khóa liên quan đến thư mục trên

linux /sys/kernel/debug/tracing/ hoặc eBPF tracing (bpftrace , bpf_trace)

Vào strings tìm tracing ta thấy được các từ khóa chọn dòng cuối

offset +59 được tham chiếu sớm nhất trong hàm


ANS: /sys/kernel/debug/tracing/tracing_on

Task11: What procfs path does the agent read to find its own executable location before self-destruction?

Câu hỏi liên quan tới hàm cmd_selfdestruct nên ta sẽ vào hàm để xem

ANS: /proc/self/exe

Task12:What command string is compared by the agent to trigger deletion of its own binary?

liên quan đến so sánh ta lại quay về hàm cmd_process nơi so sánh chuỗi nhận từ operator bằng strcmp /strncmp nhìn vào toàn bộ src thì chỉ có đoạn này là if đơn lẻ


.Đây là dòng duy nhất trong toàn bộ hàm gọi tới cmd_selfdestruct

## ANS: sdestruct

## tóm tắt quá trình malware chạy

Sau khi khởi chạy, agent khởi tạo hàng đợi io_uring và liên tục cố gắng kết nối tới máy chủ C2 tại 192.168.56.1:4445 ; nếu kết nối thất bại, nó đóng socket, chờ 120 giây rồi thử lại, lặp vô thời hạn cho tới khi thành công. Khi kết nối được thiết lập, agent chuyển sang trạng thái chờ lệnh, liên tục nhận dữ liệu từ operator và chuyển vào bộ định tuyến lệnh (process_cmd ) để so khớp và thực thi một trong 11 lệnh được hỗ trợ: thu thập thông tin hệ thống (liệt kê user đăng nhập, tiến trình đang chạy, kết nối mạng), thao tác file (nhận/gửi dữ liệu), leo quyền (quét SUID binary trong /usr/bin ), can thiệp session người dùng khác, và đặc biệt là hai lệnh mang tính phòng thủ chủ động: vô hiệu hoá công cụ giám sát dựa trên eBPF/ftrace (tắt tracing, xoá BPF pinned file, kill tiến trình liên quan), và tự xoá binary khỏi đĩa thông qua /proc/self/exe để xoá dấu vết. Vòng lặp nhận-xử lý lệnh này tiếp diễn cho tới khi operator gửi lệnh thoát hoặc kết nối bị ngắt, lúc đó agent dọn dẹp tài nguyên io_uring và tự kết thúc tiến trình
