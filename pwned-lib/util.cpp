/*
 Copyright © 2019 Oliver Lau <oliver@ersatzworld.net>
 
 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
 
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 
 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "util.hpp"

#if __APPLE__
#include <sys/types.h>
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <mach/vm_statistics.h>
#include <mach/mach_types.h>
#include <mach/mach_init.h>
#include <mach/mach_host.h>
#endif

#include <string>
#include <memory>

#include <stdio.h>
#include <termios.h>
#include <unistd.h>
#include <math.h>

namespace pwned {

    // see https://gist.github.com/gunkmogo/5d54f9fb4579768d9c7d5c41293cc784
    int getMemoryStat(MemoryStat &memoryStat) {
    #if __APPLE__
        xsw_usage vmusage = {0};
        size_t size = sizeof(vmusage);
        if (sysctlbyname("vm.swapusage", &vmusage, &size, NULL, 0) != 0) {
            return -1;
        }
        memoryStat.virt.total = vmusage.xsu_total;
        memoryStat.virt.avail = vmusage.xsu_avail;
        memoryStat.virt.used = vmusage.xsu_used;
        
        int mib[2];
        mib[0] = CTL_HW;
        mib[1] = HW_MEMSIZE;
        size_t length = sizeof(memoryStat.phys.total);
        sysctl(mib, 2, &memoryStat.phys.total, &length, NULL, 0);
        
        mach_msg_type_number_t count = HOST_VM_INFO_COUNT;
        vm_statistics_data_t vmstat;
        if(KERN_SUCCESS != host_statistics(mach_host_self(), HOST_VM_INFO, (host_info_t)&vmstat, &count)) {
            return -2;
        }
        memoryStat.phys.avail = (int64_t)vmstat.free_count * (int64_t)vmusage.xsu_pagesize;
        memoryStat.phys.used = ((int64_t)vmstat.active_count +
                                (int64_t)vmstat.inactive_count +
                                (int64_t)vmstat.wire_count) * (int64_t)vmusage.xsu_pagesize;
        
        // Get App Memory Stats
        struct task_basic_info t_info;
        mach_msg_type_number_t t_info_count = TASK_BASIC_INFO_COUNT;
        
        if (KERN_SUCCESS != task_info(mach_task_self(),
                                      TASK_BASIC_INFO, (task_info_t)&t_info,
                                      &t_info_count))
        {
            return -3;
        }
        memoryStat.virt.app = t_info.virtual_size;
        memoryStat.phys.app = t_info.resident_size;
    #endif
        return 0;
    }

    // see https://stackoverflow.com/a/8098080
    std::string string_format(const std::string fmt_str, ...) {
        int final_n, n = ((int)fmt_str.size()) * 2;
        std::unique_ptr<char[]> formatted;
        va_list ap;
        while (true) {
            formatted.reset(new char[n]);
            strcpy(&formatted[0], fmt_str.c_str());
            va_start(ap, fmt_str);
            final_n = vsnprintf(&formatted[0], n, fmt_str.c_str(), ap);
            va_end(ap);
            if (final_n < 0 || final_n >= n) {
                n += abs(final_n - n + 1);
            }
            else {
                break;
            }
        }
        return std::string(formatted.get());
    }
    
    std::string readableSize(long long size) {
        double sz = (double)size;
        if (sz > 1024LL*1024LL*1024LL*1024LL) {
            return string_format("%.1f TB", sz/1024/1024/1024/1024);
        }
        else if (size > 1024*1024*1024) {
            return string_format("%.1f GB", sz/1024/1024/1024);
        }
        else if (size > 1024*1024) {
            return string_format("%.1f MB", sz/1024/1024);
        }
        else if (size > 1024) {
            return string_format("%.1f KB", sz/1024);
        }
        return string_format("%ld B", size);
    }


    std::string readableTime(double t) {
        double x = t;
        std::string result;
        const int days = int(x/60/60/24);
        x -= double(days*60*60*24);
        const int hours = int(x/60/60);
        x -= double(hours*60*60);
        const int mins = int(x/60);
        x -= double(mins*60);
        const double secs = x;
        if (t > 60*60*24) {
            result = string_format("%dd %dh %dm %ds", days, hours, mins, secs);
        }
        else if (t > 60*60) {
            result = string_format("%dh %dm %ds", hours, mins, secs);
        }
        else if (t > 60) {
            result = string_format("%dm %ds", mins, int(round(secs)));
        }
        else {
            result = string_format("%.4fs", secs);
        }
        return result;
    }
    
    TermIO::TermIO()
    {
        tcgetattr(STDIN_FILENO, &old_t);
    }
    
    TermIO::~TermIO() {
        tcsetattr(STDIN_FILENO, TCSANOW, &old_t);
    }
    
    void TermIO::disableEcho() {
        struct termios t;
        tcgetattr(STDIN_FILENO, &t);
        t.c_lflag &= ~ICANON;
        t.c_lflag &= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &t);
    }
        
    void TermIO::enableEcho() {
        struct termios t;
        tcgetattr(STDIN_FILENO, &t);
        t.c_lflag |= ICANON;
        t.c_lflag |= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &t);
    }
    
    void TermIO::disableBreak() {
        struct termios t;
        tcgetattr(STDIN_FILENO, &t);
        t.c_lflag &= ~ISIG;
        tcsetattr(STDIN_FILENO, TCSANOW, &t);
    }
    
    void TermIO::enableBreak() {
        struct termios t;
        tcgetattr(STDIN_FILENO, &t);
        t.c_lflag |= ISIG;
        tcsetattr(STDIN_FILENO, TCSANOW, &t);
    }
}
