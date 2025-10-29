package main

// 并发改写：对每个进程使用局部任务队列 + worker pool 并行读取内存块并搜索 IOC
// 优点：
// 1) 把 VirtualQueryEx 得到的内存 region 切分成若干读取任务并发执行，减少单线程阻塞等待ReadProcessMemory的时间
// 2) 使用固定大小的 goroutine 池控制并发，不会因过多并发导致资源竞争或过度上下文切换
// 3) 把匹配输出集中到单独的打印 goroutine，避免多 goroutine 同时写 stdout 导致竞争

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/fatih/color"
	"golang.org/x/sys/windows"
)

var (
	// 系统变量相关
	ioc_string   string
	iocFileInput string
	chunkSz      = 10 * 1024 * 1024 // 10MB
	overlap_size = 200
	// 调用windows api相关
	kernel32           = windows.NewLazySystemDLL("kernel32.dll")
	procVirtualQueryEx = kernel32.NewProc("VirtualQueryEx")
	psapi              = windows.NewLazySystemDLL("psapi.dll")
	// 字体颜色相关
	boldRed    = color.New(color.FgRed).Add(color.Bold).SprintFunc()
	boldYellow = color.New(color.FgHiYellow).Add(color.Bold).SprintFunc()
	boldCyan   = color.New(color.FgCyan).Add(color.Bold).SprintFunc()
	gray       = color.New(color.FgHiBlack).SprintFunc()
)

// 用于统计
var result_count_map = make(map[string]*ProcessInfo)
var mu sync.Mutex

var skipWhitePaths = map[string]struct{}{
	"C:\\Windows\\System32\\svchost.exe":                                                 {},
	"C:\\Windows\\System32\\ShellHost.exe":                                               {},
	"C:\\Windows\\System32\\sihost.exe":                                                  {},
	"C:\\Windows\\SystemApps\\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\\SearchHost.exe": {},
	"C:\\Windows\\explorer.exe":                                                          {},
	"C:\\Windows\\System32\\backgroundTaskHost.exe":                                      {},
}

type ProcessInfo struct {
	Count      int
	selfPID    uint32
	selfPath   string
	parentPID  uint32
	parentName string
	parentPath string
	snippet    map[string]struct{}
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	flag.StringVar(&ioc_string, "ioc", "", "Comma-separated IOC strings to search")
	flag.StringVar(&iocFileInput, "iocfile", "", "File with IOC strings (one per line)")
	flag.Parse()
	if ioc_string == "" && iocFileInput == "" {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("请输入 IOC ，多个IOC以英文逗号（,）分隔, 回车确认\n")
		ioc_string, _ = reader.ReadString('\n')
		ioc_string = strings.TrimSpace(ioc_string)

		fmt.Print("请输入 IOC 文件路径（如 \"C:\\ioc.txt）\"，或回车跳过: \n")
		iocFileInput, _ = reader.ReadString('\n')
		iocFileInput = strings.TrimSpace(iocFileInput)

	}
	// tmp := ["aslkjdlkj.com"]

	ioc_list, err := loadIOCs(ioc_string, iocFileInput)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("您输入的IOC为%v ", ioc_list)

	// // 这里为了示例直接写 iocs
	// iocs := []string{"aslkjdlkj.com"}

	if len(ioc_list) == 0 {
		fmt.Fprintln(os.Stderr, "No IOC provided. Use -ioc or -iocfile。 请输入IOC")
		os.Exit(1)
	}

	maxLen := 0
	for _, s := range ioc_list {
		if l := len(s); l > maxLen {
			maxLen = l
		}
	}
	if maxLen+16 > overlap_size {
		overlap_size = maxLen + 16
	}

	fmt.Printf("IOCs=%v  overlap=%d  chunk=%d platform=windows\n", ioc_list, overlap_size, chunkSz)
	t2 := time.Now()
	if err := windowsSearch(ioc_list); err != nil {
		fmt.Fprintf(os.Stderr, "search error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("总计用时 %v\n", time.Since(t2))

	fmt.Printf("IOC命中统计结果如下，详情请见上日志\n")
	printResultMap(result_count_map)

	fmt.Println("程序执行完毕。")
	fmt.Println("按回车键退出...")
	fmt.Scanln() // 等待用户输入，防止窗口自动关闭
}

func loadIOCs(list, file string) ([]string, error) {
	var ioc_list []string
	if file != "" {
		f, err := os.Open(file)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line != "" {
				ioc_list = append(ioc_list, line)
			}
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	if list != "" {
		parts := strings.Split(list, ",")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				ioc_list = append(ioc_list, p)
			}
		}
	}
	slices.Sort(ioc_list)
	// 所有ioc转换为小写
	for i, v := range ioc_list {
		ioc_list[i] = strings.ToLower(v)
	}
	return slices.Compact(ioc_list), nil
}

// windowsSearch: 遍历进程, 对每个进程并发扫描其内存
func windowsSearch(iocs []string) error {

	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return err
	}
	fmt.Printf("获取镜像完成\n")
	defer windows.CloseHandle(snapshot)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))

	process_32_err := windows.Process32First(snapshot, &pe)

	type processTask struct {
		hProc      windows.Handle
		iocs       []string
		pid        uint32
		pname      string
		ppath      string
		parentPID  uint32
		parentName string
		parentPath string
	}
	var wg sync.WaitGroup
	workerCount := min(max(runtime.NumCPU()*2, 2), 16)
	taskCh := make(chan processTask, workerCount*4)
	ParentPidCounterMap := make(map[uint32]int)
	// worker消费者
	fmt.Printf("正在开始扫描进程\n")
	for i := 0; i < runtime.NumCPU()*2; i++ {
		wg.Go(func() {
			for t := range taskCh {
				// scanProcess(t)
				err := scanProcessMemoryConcurrent(t.hProc, t.iocs, t.pid, t.pname, t.ppath, t.parentPID, t.parentName, t.parentPath)
				if err != nil {
					fmt.Printf("扫描进程 %s (PID %d) 时出错: %v\n", t.pname, t.pid, err)
				}
				windows.CloseHandle(t.hProc)

			}
		})
	}

	// 生产者
	for process_32_err == nil {
		pid := pe.ProcessID
		parent_pid := pe.ParentProcessID
		pname := windows.UTF16ToString(pe.ExeFile[:])

		hProc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_VM_READ, false, pid)

		if err != nil {
			process_32_err = windows.Process32Next(snapshot, &pe)
			continue
		}
		// 获取内存大小
		memSize, err := getProcessMemory(hProc)
		if err != nil {
			fmt.Println("GetProcessMemory failed:", err)
			memSize = 0
		}
		// fmt.Printf("ParentPID=%d PID=%d name=%s Memory=%.2f MB\n", parent_pid, pid, pname, float64(memSize)/1024/1024)
		// 根据内存大小进行过滤，提高速度，500MB以上的软件就不检测了。
		if memSize >= 500*1024*1024 {
			// fmt.Printf("ParentPID=%d PID=%d name=%s 占用内存大于500MB，跳过\n", parent_pid, pid, pname)
			windows.CloseHandle(hProc)
			process_32_err = windows.Process32Next(snapshot, &pe)
			continue
		}

		// 获取父一级进程大小size
		var parentMem uint64
		var parentName string
		var parentPath string
		if parent_pid > 0 {
			hParent, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_VM_READ, false, parent_pid)
			if err == nil {
				parentMem, _ = getProcessMemory(hParent)

				var buf [syscall.MAX_PATH]uint16
				size := uint32(len(buf))
				if qErr := windows.QueryFullProcessImageName(hParent, 0, &buf[0], &size); qErr == nil {
					parentPath = syscall.UTF16ToString(buf[:size])
					parentName = filepath.Base(parentPath)
				} else {
					parentName = ""
					parentPath = ""
				}

				windows.CloseHandle(hParent)
			} else {
				parentMem = 0
				parentName = ""
				parentPath = ""
			}
		} else {
			parentMem = 0
			parentName = ""
			parentPath = ""
		}
		ParentPidCounterMap[parent_pid]++
		if ParentPidCounterMap[parent_pid] >= 10 && parentPath != "" {
			// fmt.Printf("%d，子进程数超过10个，跳过，名称 %v 路径%v\n", parent_pid, parentExe, parentPath)
			process_32_err = windows.Process32Next(snapshot, &pe)
			continue
		}

		// if strings.HasPrefix(parentPath, "C:\\Windows\\") || strings.HasPrefix(parentPath, "C:\\Program Files\\WindowsApps\\") {
		// 	fmt.Printf("%d，为可信目录，跳过，名称 %v 路径%v\n", parent_pid, parentExe, parentPath)
		// 	process_32_err = windows.Process32Next(snapshot, &pe)
		// 	continue
		// }

		// 父一级进程大小过滤
		if parentMem >= 500*1024*1024 {
			// fmt.Printf("PID: %d, Parent PID: %d, Name: %s, Mem: %.2f MB, Parent Mem: %.2f MB 父进程占用超过500MB跳过\n",
			// pid, parent_pid, pname, float64(memSize)/1024/1024, float64(parentMem)/1024/1024)
			process_32_err = windows.Process32Next(snapshot, &pe)
			continue
		}

		//获取进程路径
		var buf [syscall.MAX_PATH]uint16
		var size uint32 = syscall.MAX_PATH
		selfpath := ""
		err = windows.QueryFullProcessImageName(hProc, 0, &buf[0], &size)
		if err == nil {
			selfpath = syscall.UTF16ToString(buf[:size])
		}

		if _, ok := skipWhitePaths[selfpath]; ok {
			windows.CloseHandle(hProc)
			process_32_err = windows.Process32Next(snapshot, &pe)
			continue
		}

		// if parentPath == "" {
		// 	if strings.HasPrefix(selfpath, "C:\\Windows\\") || strings.HasPrefix(selfpath, "C:\\Program Files\\WindowsApps\\") {
		// 		fmt.Printf("%d，为可信目录，跳过，名称 %v 路径%v\n", parent_pid, parentExe, selfpath)
		// 		process_32_err = windows.Process32Next(snapshot, &pe)
		// 		continue
		// 	}
		// }

		// fmt.Printf("PID: %d, Parent PID: %d, Name: %s,path: %s, Mem: %.2f MB, Parent Mem: %.2f MB, 父进程名称：%s，父进程路径：%s 开始扫描内存\n",
		// 	pid, parent_pid, pname, selfpath, float64(memSize)/1024/1024, float64(parentMem)/1024/1024, parentExe, parentPath)
		// _ = parentExe
		// 并发扫描单个进程
		// err = scanProcessMemoryConcurrent(hProc, iocs, pid, pname, ppath)
		taskCh <- processTask{hProc, iocs, pid, pname, selfpath, parent_pid, parentName, parentPath}

		if err != nil {
			fmt.Printf("扫描进程 %s (PID %d) 时出错: %v\n", pname, pid, err)
		}

		process_32_err = windows.Process32Next(snapshot, &pe)
	}

	close(taskCh)
	wg.Wait()
	return nil
}

func getProcessMemory(h windows.Handle) (uint64, error) {
	var mem struct {
		cb                         uint32
		PageFaultCount             uint32
		PeakWorkingSetSize         uintptr
		WorkingSetSize             uintptr
		QuotaPeakPagedPoolUsage    uintptr
		QuotaPagedPoolUsage        uintptr
		QuotaPeakNonPagedPoolUsage uintptr
		QuotaNonPagedPoolUsage     uintptr
		PagefileUsage              uintptr
		PeakPagefileUsage          uintptr
	}
	mem.cb = uint32(unsafe.Sizeof(mem))

	proc := psapi.NewProc("GetProcessMemoryInfo")
	r1, _, err := proc.Call(uintptr(h), uintptr(unsafe.Pointer(&mem)), uintptr(mem.cb))
	if r1 == 0 {
		return 0, err
	}
	return uint64(mem.WorkingSetSize), nil
}

// Task 表示需要读取并搜索的内存块
type task struct {
	addr        uintptr
	size        uintptr
	regionStart uint64
	regionEnd   uint64
}

// scanProcessMemoryConcurrent: 为每个进程建立固定大小的 worker pool 来并行读取内存并搜索 ioc
func scanProcessMemoryConcurrent(hProc windows.Handle, iocs []string, pid uint32, pname, ppath string, parentPid uint32, parentName string, parentPath string) error {
	var memInfo windows.MemoryBasicInformation
	var addr uintptr

	// 提前定义需要收集和跳过的内存基址
	type region struct {
		base uintptr
		size uintptr
	}
	var regions_list []region
	var lastEnd uintptr

	workerCount := min(max(runtime.NumCPU()*2, 2), 16)
	taskCh := make(chan task, workerCount*4)
	// 先收集所有需要扫描的 region -> 转成小块任务
	// var tasks []task

	for addr = 0; addr < 0x7fffffffffff; {
		// 用于查询 指定进程虚拟地址空间 中某个地址对应的 内存信息
		err := VirtualQueryEx(hProc, addr, &memInfo)
		if err != nil {
			break

		}

		// 过滤零页、空洞
		// || 或
		if memInfo.Protect&windows.PAGE_NOACCESS != 0 || memInfo.State != windows.MEM_COMMIT {
			addr += memInfo.RegionSize
			continue
		}

		// 扫描区域大于512MB时过滤，提升速度，恶意可能性较小
		if memInfo.RegionSize > 512*1024*1024 {
			addr += memInfo.RegionSize
			continue // 跳过单个超大内存块
		}
		// 只处理 MEM_COMMIT 且为可读的区域
		if memInfo.State == windows.MEM_COMMIT && (memInfo.Protect == windows.PAGE_READWRITE || memInfo.Protect == windows.PAGE_READONLY || memInfo.Protect == windows.PAGE_EXECUTE_READ) && memInfo.Protect&windows.PAGE_NOACCESS == 0 && memInfo.Protect&windows.PAGE_GUARD == 0 {
			// 保留
		} else {
			addr += memInfo.RegionSize
			continue
		}

		// 如果当前 region 与上一个可读 region 相邻或间隔小于 4KB，则合并
		// lastEnd!=0:跳过第一个轮询。memInfo.BaseAddress-lastEnd < 4096：当前基址距离上个基址小于4096，则合并

		// 间隙大小
		size_between_region := memInfo.BaseAddress - lastEnd
		if lastEnd != 0 && size_between_region < 4096 {
			// 读取上一个region regions_list[len(regions_list)-1].size的大小，增加间隙大小和当前region大小
			regions_list[len(regions_list)-1].size += memInfo.RegionSize + size_between_region
			lastEnd = memInfo.BaseAddress + memInfo.RegionSize
		} else {
			regions_list = append(regions_list, region{
				base: memInfo.BaseAddress,
				size: memInfo.RegionSize,
			})

			lastEnd = memInfo.BaseAddress + memInfo.RegionSize
		}
		addr += memInfo.RegionSize
	}

	go func() {
		for _, r := range regions_list {
			offset := uintptr(0)
			for offset < r.size {
				toRead := min(uintptr(chunkSz), r.size-offset)

				// r.base 该region内 内存基址
				// offset region内的偏移量
				// addr =r.base+offset 本次开始读取地址
				// size 读取大小
				//
				taskCh <- task{
					addr:        r.base + offset,         // 要读取的内存起始地址
					size:        toRead,                  // 要读取的字节数
					regionStart: uint64(r.base),          // region 起始地址
					regionEnd:   uint64(r.base + r.size), // region 结束地址
				}

				if toRead > uintptr(overlap_size) {
					offset += toRead - uintptr(overlap_size)
				} else {
					offset += toRead
				}
			}
		}
		close(taskCh)
	}()

	matches := make(chan string, 128)

	// 两个 WaitGroup：一个等待 worker 完成，一个等待 printer 完成
	var wgWorkers sync.WaitGroup
	var wgPrinter sync.WaitGroup

	// 输出 goroutine（单独 wgPrinter 管理）
	wgPrinter.Go(func() {
		for m := range matches {
			fmt.Println(m)
		}
	})

	// worker pool

	// 声明chan通道，通道是特殊类型，保证先入先出
	// taskCh := make(chan task, workerCount*4)
	// fmt.Printf("当前核数 %d,当前并发数%d", workerCount, len(taskCh))
	// 启动 workerCount 个 worker，由 wgWorkers 管理，定义worker需要执行的操作
	// 类似为先启动空的异步任务，定义需要做的事，然后在后面往channel中塞任务
	for range workerCount {
		wgWorkers.Go(func() {
			// 从taskChannel中不断接受任务
			buf := make([]byte, chunkSz)
			for t := range taskCh {
				// 为每个任务分配缓冲（可后续改为 sync.Pool 以减少分配）
				if len(buf) < int(t.size) {
					buf = make([]byte, int(t.size))
				}

				// 改为syncPool来重用内存
				// var bufPool = sync.Pool{
				// 	New: func() any { return make([]byte, chunkSz) },
				// }

				// buf := bufPool.Get().([]byte)
				// defer bufPool.Put(buf)

				var n uintptr
				// 读取内存
				// t0 := time.Now()
				err := windows.ReadProcessMemory(hProc, t.addr, &buf[0], t.size, &n)
				// if time.Since(t0) >= 200*time.Millisecond {
				// 	// 可选的性能日志
				// 	fmt.Printf("读取内存 PID=%d [%s] addr=0x%x size=%d 耗时 %v\n", pid, pname, t.addr, t.size, time.Since(t0))
				// }

				if err != nil || n == 0 {
					// 读取失败或没有数据，跳过该任务
					continue
				}
				buf = buf[:int(n)]

				// 对每个 ioc 进行匹配
				var sb strings.Builder
				for _, ioc := range iocs {
					idx := indexIgnoreCaseBytesbmh(buf, []byte(ioc))
					if idx >= 0 {
						iocAddr := uint64(t.addr) + uint64(idx)
						start := max(idx-40, 0)
						end := min(idx+len(ioc)+40, len(buf))
						snippet := sanitizeSnippet(buf[start:end])
						// 将结果发送到 matches（缓冲 channel 减少阻塞）

						// sb.WriteString(fmt.Sprintf("%s %s=%d %s=\"%s\" %s=\"%s\" %s=0x%x %s=[0x%x-0x%x] %s=\"%s\" %s=\"%s\"", boldRed("[Match]"), boldRed("进程ID"),
						// 	pid, boldRed("进程名"), pname, boldRed("路径"), ppath, boldRed("Addr"), uintptr(iocAddr), boldRed("REGION"), t.regionStart, t.regionEnd, boldRed("IoC"), ioc, boldRed("上下文"), snippet))
						// matches <- fmt.Sprintf("[MATCH] PID=%d Name=\"%s\" Path=\"%s\" ADDR=0x%x REGION=[0x%x-0x%x] IOC=\"%s\" SNIPPET=\"%s\"",
						// 	pid, pname, ppath, iocAddr, t.regionStart, t.regionEnd, ioc, snippet)

						sb.WriteString(fmt.Sprintf("%s %s=%d %s=\"%s\" %s=\"%s\"\n",
							boldRed("[Match]"),
							boldYellow("PID"), pid,
							boldYellow("Name"), pname,
							boldYellow("Path"), ppath,
						))

						sb.WriteString(fmt.Sprintf("  %s=0x%x %s=[0x%x-0x%x] %s=\"%s\"\n",
							boldCyan("ADDR"), uintptr(iocAddr),
							boldCyan("REGION"), t.regionStart, t.regionEnd,
							boldCyan("IOC"), ioc,
						))

						sb.WriteString(fmt.Sprintf("  %s=\"%s\"\n\n",
							boldYellow("SNIPPET"), gray(snippet),
						))

						matches <- sb.String()
						sb.Reset()

						result_count(result_count_map, pname, pid, ppath, parentPid, parentName, parentPath, snippet)
					}
				}
			}
		})
	}

	// feed tasks - 由主 goroutine 或单独 goroutine 发入 taskCh，然后 close(taskCh)
	// go func() {
	// 	// 从之前创建的tasks中不断的发送任务到channel中
	// 	for _, t := range tasks {
	// 		taskCh <- t
	// 	}
	// 	close(taskCh) // 任务全部发送完毕，关闭 taskCh，worker 会在取尽后退出循环
	// }()

	// 等待所有 worker 完成（即他们不再写 matches）
	wgWorkers.Wait()

	// 所有 worker 都已结束，不会再向 matches 写入，安全地 close(matches)
	close(matches)

	// 等待 printer 把 matches 中剩余的结果都打印完毕
	wgPrinter.Wait()

	return nil
}

func VirtualQueryEx(hProc windows.Handle, addr uintptr, mbi *windows.MemoryBasicInformation) error {
	ret, _, err := procVirtualQueryEx.Call(
		uintptr(hProc),
		addr,
		uintptr(unsafe.Pointer(mbi)),
		unsafe.Sizeof(*mbi),
	)
	if ret == 0 {
		if err != nil && err != syscall.Errno(0) {
			return err
		}
		return syscall.EINVAL
	}
	return nil
}

// 更高效的忽略大小写搜索：以 patternLower(全小写) 为基础，逐字扫描 buf 找到首字母，然后逐字比较小写
// func indexIgnoreCaseBytes(buf []byte, patternLower []byte, firstLower byte, firstUpper byte) int {
// 	n := len(buf)
// 	m := len(patternLower)
// 	if m == 0 || n < m {
// 		return -1
// 	}

// 	pos := 0
// 	for pos <= n-m {
// 		// 找到可能的起点（匹配首字母的 either lower/upper）
// 		b := buf[pos]
// 		if b != firstLower && b != firstUpper {
// 			// 快速跳过到下一个可能匹配字节
// 			// 这里简单+1就足够，避免频繁转换
// 			pos++
// 			continue
// 		}
// 		// 检查是否匹配
// 		matched := true
// 		for j := range m {
// 			if toLowerASCIIByte(buf[pos+j]) != patternLower[j] {
// 				matched = false
// 				break
// 			}
// 		}
// 		if matched {
// 			return pos
// 		}
// 		pos++
// 	}
// 	return -1
// }

func indexIgnoreCaseBytesbmh(buf []byte, patternLower []byte) int {
	n := len(buf)
	m := len(patternLower)
	if m == 0 || n < m {
		return -1
	}

	// === Step 1. 构建跳表（skip table）===
	// 构建一个256长度的list，每个元素都是ioc的长度

	skip := make([]int, 256)
	for i := range skip {
		skip[i] = m
	}
	// fmt.Printf("%v", skip)
	for i := 0; i < m-1; i++ {
		c := patternLower[i]
		skip[c] = m - 1 - i
		if c >= 'a' && c <= 'z' {
			skip[c-32] = m - 1 - i // 填充大写映射
		}
	}

	// === Step 2. 主匹配循环 ===
	i := 0
	for i <= n-m {
		last := buf[i+m-1]
		lastLower := toLowerASCIIByte(last)

		if lastLower == patternLower[m-1] {
			// 尝试完全匹配
			match := true
			for j := 0; j < m; j++ {
				if toLowerASCIIByte(buf[i+j]) != patternLower[j] {
					match = false
					break
				}
			}
			if match {
				return i
			}
		}
		i += skip[lastLower]
	}
	return -1
}

func toLowerASCIIByte(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + 32
	}
	return b
}

func sanitizeSnippet(b []byte) string {
	var out []rune
	for _, ch := range string(b) {
		if ch >= 32 && ch <= 126 {
			out = append(out, ch)
		} else {
			out = append(out, '.')
		}
		if len(out) > 200 {
			break
		}
	}
	return string(out)
}

// type ProcessInfo struct {
// 	Count      int
// 	selfPID    string
// 	selfPath   string
// 	parentPID  string
// 	parentPath string
// 	snippet    string
// }

func result_count(m map[string]*ProcessInfo, selfName string, selfPID uint32, selfPath string, parentPID uint32, parentName string, parentPath string, snippet string) {
	mu.Lock()
	defer mu.Unlock()
	if info, exists := m[selfName]; exists {
		info.Count++ // 已存在，累加
		info.snippet[snippet] = struct{}{}
	} else {

		m[selfName] = &ProcessInfo{
			Count:      1, // 第一次出现，初始值 1
			selfPID:    selfPID,
			selfPath:   selfPath,
			parentPID:  parentPID,
			parentName: parentName,
			parentPath: parentPath,
			snippet:    map[string]struct{}{snippet: {}},
		}
	}

}

func printResultMap(result_count_map map[string]*ProcessInfo) {
	// 定义一些颜色函数
	boldCyan := color.New(color.FgCyan, color.Bold).SprintFunc()     // 用于标题
	boldYellow := color.New(color.FgYellow, color.Bold).SprintFunc() // 字段名
	red := color.New(color.FgRed).SprintFunc()                       // 关键数值
	green := color.New(color.FgGreen).SprintFunc()                   // 命中次数
	white := color.New(color.FgWhite).SprintFunc()                   // 普通文本

	for name, info := range result_count_map {
		snippet_string := ""
		for s := range info.snippet {
			snippet_string = s + "\n"
		}
		// 打印标题和分割线
		fmt.Println(boldCyan("-------- 进程:", name, "--------"))

		// 打印详细信息，每行一类
		fmt.Printf("%s: %s\n", boldYellow("进程名"), white(name))
		fmt.Printf("%s: %s\n", boldYellow("PID"), red(info.selfPID))
		fmt.Printf("%s: %s\n", boldYellow("路径"), white(info.selfPath))
		fmt.Printf("%s: %s\n", boldYellow("命中次数"), green(info.Count))
		fmt.Printf("%s: %s\n", boldYellow("父进程名称"), white(info.parentName))
		fmt.Printf("%s: %s\n", boldYellow("父进程 PID"), red(info.parentPID))
		fmt.Printf("%s: %s\n", boldYellow("父进程路径"), white(info.parentPath))
		fmt.Printf("%s: %v\n", boldYellow("命中上下文"), white(snippet_string))

		// 打印底部分割线
		fmt.Println(boldCyan("------------------------------------------------\n"))
	}
}
