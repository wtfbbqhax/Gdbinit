# ~/.gdbinit

#source ~/.gdbinit.py

set extended-prompt \e[1m\]\e[38;5;196m\]- GNU Debugger \v -----------------------------------------------------------------------------------------------\e[0m\]\n>>>\ 

# Uncomment if you use vagrant and trust your files - VJR
#set auto-load safe-path /home/vagrant/
set disassembly-flavor intel

set confirm off
set verbose off

set history filename ~/.gdbhist
set history save

#set output-radix 0x10
#set input-radix  0x10

set print pretty
set print array 
set print array-indexes

# These make gdb never pause in its output
set height 0
set width  0

# voidwalker is much more powerful but has flaky support on my systems - VJR
#python from voidwalker import voidwalker
#define hook-stop
#  voidwalker hook-stop
#end

# set to 0 to remove display of cpu registers
set $SHOWCPUREGISTERS = 1
# set to 1 to enable display of stack
set $SHOWSTACK = 0
# set to 1 to enable display of data window 
set $SHOWDATAWIN = 0
# set to 0 to disable colored display of changed registers
set $SHOWREGCHANGES = 0
# use colorized output or not
set $USECOLOR = 1

# set $64BITS = 0 if your debugging 32bit executables - VJR
set $64BITS = 1


set $SHOW_CONTEXT      = 1
set $SHOW_NEST_INSN    = 0
set $CONTEXTSIZE_STACK = 6
set $CONTEXTSIZE_DATA  = 8
set $CONTEXTSIZE_CODE  = 8

                                         

####################################################################
####################################################################

set $BLACK      = 0
set $RED        = 1
set $GREEN      = 2
set $YELLOW     = 3
set $BLUE       = 4
set $MAGENTA    = 5
set $CYAN       = 6
set $WHITE      = 7

set $COLOR_REGNAME          = $GREEN
set $COLOR_REGVAL           = $WHITE
set $COLOR_REGVAL_MODIFIED  = $RED
set $COLOR_SEPARATOR        = $BLUE
set $COLOR_CPUFLAGS         = $RED

define fg_print
    printf "%c[38;5;%02dm", $arg0
end

define setstyle
    printf "%c[%d;3%dm", 033, $arg0, $arg1
end

define color
    setstyle 0 $arg0
end
define color_reset
   echo \033[0m
end
define color_bold
    echo \033[1m
end
define color_underline
    echo \033[4m
end

# Initialize these variables else comparisons will fail for coloring
# we must initialize all of them at once, 32 and 64 bits
set $oldrax = 0
set $oldrbx = 0
set $oldrcx = 0
set $oldrdx = 0
set $oldrsi = 0
set $oldrdi = 0
set $oldrbp = 0
set $oldrsp = 0
set $oldr8  = 0
set $oldr9  = 0
set $oldr10 = 0
set $oldr11 = 0
set $oldr12 = 0
set $oldr13 = 0
set $oldr14 = 0
set $oldr15 = 0
set $oldeax = 0
set $oldebx = 0
set $oldecx = 0
set $oldedx = 0
set $oldesi = 0
set $oldedi = 0
set $oldebp = 0
set $oldesp = 0

# ______________window size control___________
define contextsize-stack
    if $argc != 1
        help contextsize-stack
    else
        set $CONTEXTSIZE_STACK = $arg0
    end
end
document contextsize-stack
Syntax: contextsize-stack NUM
| Set stack dump window size to NUM lines.
end


define contextsize-data
    if $argc != 1
        help contextsize-data
    else
        set $CONTEXTSIZE_DATA = $arg0
    end
end
document contextsize-data
Syntax: contextsize-data NUM
| Set data dump window size to NUM lines.
end


define contextsize-code
    if $argc != 1
        help contextsize-code
    else
        set $CONTEXTSIZE_CODE = $arg0
    end
end
document contextsize-code
Syntax: contextsize-code NUM
| Set code window size to NUM lines.
end

# ______________process information____________
define frameprint
    info frame
    info args
    info locals
end

define flagsx86
    # OF (overflow) flag
    if (((unsigned int)$eflags >> 0xB) & 1)
        echo O\ 
        set $_of_flag = 1
    else
        echo o\ 
        set $_of_flag = 0
    end
    # DF (direction) flag
    if (((unsigned int)$eflags >> 0xA) & 1)
        echo D\ 
    else
        echo d\ 
    end
    # IF (interrupt enable) flag
    if (((unsigned int)$eflags >> 9) & 1)
        echo I\ 
    else
        echo i\ 
    end
    # TF (trap) flag
    if (((unsigned int)$eflags >> 8) & 1)
        echo T\ 
    else
        echo t\ 
    end
    # SF (sign) flag
    if (((unsigned int)$eflags >> 7) & 1)
        echo S\ 
        set $_sf_flag = 1
    else
        echo s\ 
        set $_sf_flag = 0
    end
    # ZF (zero) flag
    if (((unsigned int)$eflags >> 6) & 1)
        echo Z\ 
        set $_zf_flag = 1
    else
        echo z\ 
        set $_zf_flag = 0
    end
    # AF (adjust) flag
    if (((unsigned int)$eflags >> 4) & 1)
        echo A\ 
    else
        echo a\ 
    end
    # PF (parity) flag
    if (((unsigned int)$eflags >> 2) & 1)
        echo P\ 
        set $_pf_flag = 1
    else
        echo p\ 
        set $_pf_flag = 0
    end
    # CF (carry) flag
    if ((unsigned int)$eflags & 1)
        echo C\ 
        set $_cf_flag = 1
    else
        echo c\ 
        set $_cf_flag = 0
    end
    echo \n
end
document flagsx86
Syntax: flagsx86
| Auxiliary function to set X86/X64 cpu flags.
end


define flags
    # call the auxiliary functions based on target cpu
    flagsx86
end
document flags
Syntax: flags
| Print flags register.
end


define eflags
    printf "     OF <%d>  DF <%d>  IF <%d>  TF <%d>",\
           (((unsigned int)$eflags >> 0xB) & 1), (((unsigned int)$eflags >> 0xA) & 1), \
           (((unsigned int)$eflags >> 9) & 1), (((unsigned int)$eflags >> 8) & 1)
    printf "  SF <%d>  ZF <%d>  AF <%d>  PF <%d>  CF <%d>\n",\
           (((unsigned int)$eflags >> 7) & 1), (((unsigned int)$eflags >> 6) & 1),\
           (((unsigned int)$eflags >> 4) & 1), (((unsigned int)$eflags >> 2) & 1), ((unsigned int)$eflags & 1)
    printf "     ID <%d>  VIP <%d> VIF <%d> AC <%d>",\
           (((unsigned int)$eflags >> 0x15) & 1), (((unsigned int)$eflags >> 0x14) & 1), \
           (((unsigned int)$eflags >> 0x13) & 1), (((unsigned int)$eflags >> 0x12) & 1)
    printf "  VM <%d>  RF <%d>  NT <%d>  IOPL <%d>\n",\
           (((unsigned int)$eflags >> 0x11) & 1), (((unsigned int)$eflags >> 0x10) & 1),\
           (((unsigned int)$eflags >> 0xE) & 1), (((unsigned int)$eflags >> 0xC) & 3)
end
document eflags
Syntax: eflags
| Print eflags register.
end

#define cpsr
#  eflags
#end
#document cpsr
#Syntax: cpsr
#| Print cpsr register.
#end

define regx64
    # 64bits stuff
    # RAX
    color $COLOR_REGNAME
    printf "RAX:"
    if ($rax != $oldrax && $SHOWREGCHANGES == 1)
        color $COLOR_REGVAL_MODIFIED
    else
        color $COLOR_REGVAL
    end
    printf " %016lx  ", $rax
    # RBX
    color $COLOR_REGNAME
    printf "RBX:"
    if ($rbx != $oldrbx && $SHOWREGCHANGES == 1)
        color $COLOR_REGVAL_MODIFIED
    else
        color $COLOR_REGVAL
    end
    printf " %016lx  ", $rbx
    # RBP
    color $COLOR_REGNAME
    printf "RBP:"
    if ($rbp != $oldrbp && $SHOWREGCHANGES == 1)
        color $COLOR_REGVAL_MODIFIED
    else
        color $COLOR_REGVAL
    end
    printf " %016lx  ", $rbp
    # RSP
    color $COLOR_REGNAME
    printf "RSP:"
    if ($rsp != $oldrsp && $SHOWREGCHANGES == 1)
        color $COLOR_REGVAL_MODIFIED
    else
        color $COLOR_REGVAL
    end
    printf " %016lx  ", $rsp
    color_bold
    color_underline
    color $COLOR_CPUFLAGS
    flags
    color_reset
    # RDI
    color $COLOR_REGNAME
    printf "RDI:"
    if ($rdi != $oldrdi && $SHOWREGCHANGES == 1)
            color $COLOR_REGVAL_MODIFIED
    else
        color $COLOR_REGVAL
    end
    printf " %016lx  ", $rdi
    # RSI
    color $COLOR_REGNAME
    printf "RSI:"
    if ($rsi != $oldrsi && $SHOWREGCHANGES == 1)
        color $COLOR_REGVAL_MODIFIED
    else
        color $COLOR_REGVAL
    end
    printf " %016lx  ", $rsi
    # RDX
    color $COLOR_REGNAME
    printf "RDX:"
    if ($rdx != $oldrdx && $SHOWREGCHANGES == 1)
        color $COLOR_REGVAL_MODIFIED
    else
        color $COLOR_REGVAL
    end
    printf " %016lx  ", $rdx
    # RCX
    color $COLOR_REGNAME
    printf "RCX:"
    if ($rcx != $oldrcx && $SHOWREGCHANGES == 1)
        color $COLOR_REGVAL_MODIFIED
    else
        color $COLOR_REGVAL
    end
    printf " %016lx  ", $rcx
    # RIP
    color $COLOR_REGNAME
    printf "RIP:"
    color $COLOR_REGVAL_MODIFIED
    printf " %016lx\n", $rip
    # R8
    color $COLOR_REGNAME
    printf "R8 :"
    if ($r8 != $oldr8 && $SHOWREGCHANGES == 1)
        color $COLOR_REGVAL_MODIFIED
    else
        color $COLOR_REGVAL
    end
    printf " %016lx  ", $r8
    # R9
    color $COLOR_REGNAME
    printf "R9 :"
    if ($r9 != $oldr9 && $SHOWREGCHANGES == 1)
        color $COLOR_REGVAL_MODIFIED
    else
        color $COLOR_REGVAL
    end
    printf " %016lx  ", $r9
    # R10
    color $COLOR_REGNAME
        printf "R10:"
    if ($r10 != $oldr10 && $SHOWREGCHANGES == 1)
        color $COLOR_REGVAL_MODIFIED
    else
        color $COLOR_REGVAL
    end
    printf " %016lx  ", $r10
    # R11
        color $COLOR_REGNAME
    printf "R11:"
    if ($r11 != $oldr11 && $SHOWREGCHANGES == 1)
        color $COLOR_REGVAL_MODIFIED
    else
        color $COLOR_REGVAL
    end
    printf " %016lx  ", $r11
    # R12
    color $COLOR_REGNAME
    printf "R12:"
    if ($r12 != $oldr12 && $SHOWREGCHANGES == 1)
        color $COLOR_REGVAL_MODIFIED
    else
        color $COLOR_REGVAL
    end
    printf " %016lx\n", $r12
    # R13
    color $COLOR_REGNAME
    printf "R13:"
    if ($r13 != $oldr13 && $SHOWREGCHANGES == 1)
        color $COLOR_REGVAL_MODIFIED
    else
        color $COLOR_REGVAL
    end
    printf " %016lx  ", $r13
    # R14
    color $COLOR_REGNAME
    printf "R14:"
    if ($r14 != $oldr14 && $SHOWREGCHANGES == 1)
        color $COLOR_REGVAL_MODIFIED
    else
        color $COLOR_REGVAL
    end
    printf " %016lx  ", $r14
    # R15
        color $COLOR_REGNAME
    printf "R15:"
    if ($r15 != $oldr15 && $SHOWREGCHANGES == 1)
        color $COLOR_REGVAL_MODIFIED
    else
        color $COLOR_REGVAL
    end
    printf " %016lx\n", $r15
    color $COLOR_REGNAME
    printf "CS:"
    color $COLOR_REGVAL
    printf " %04x  ", $cs
    color $COLOR_REGNAME
    printf "DS:"
    color $COLOR_REGVAL
    printf " %04x  ", $ds
    color $COLOR_REGNAME
    printf "ES:"
    color $COLOR_REGVAL
    printf " %04x  ", $es
    color $COLOR_REGNAME
    printf "FS:"
    color $COLOR_REGVAL
    printf " %04x  ", $fs
    color $COLOR_REGNAME
    printf "GS:"
    color $COLOR_REGVAL
    printf " %04x  ", $gs
    color $COLOR_REGNAME
    printf "SS:"
    color $COLOR_REGVAL
    printf " %04x", $ss
    color_reset
end
document regx64
Syntax: regx64
| Auxiliary function to display X86_64 registers.
end


define regx86
    # EAX
    color $COLOR_REGNAME
        printf "  EAX:"
    if ($eax != $oldeax && $SHOWREGCHANGES == 1)
                color $COLOR_REGVAL_MODIFIED
        else
                color $COLOR_REGVAL
        end
        printf " 0x%08X  ", $eax
        # EBX
    color $COLOR_REGNAME
        printf "EBX:"
        if ($ebx != $oldebx && $SHOWREGCHANGES == 1) 
            color $COLOR_REGVAL_MODIFIED                
        else
            color $COLOR_REGVAL
        end
        printf " 0x%08X  ", $ebx
        # ECX
    color $COLOR_REGNAME
        printf "ECX:"
        if ($ecx != $oldecx && $SHOWREGCHANGES == 1)
            color $COLOR_REGVAL_MODIFIED
        else
            color $COLOR_REGVAL
        end
        printf " 0x%08X  ", $ecx
        # EDX
        color $COLOR_REGNAME
        printf "EDX:"
        if ($edx != $oldedx && $SHOWREGCHANGES == 1)
            color $COLOR_REGVAL_MODIFIED
        else
            color $COLOR_REGVAL
        end
        printf " 0x%08X  ", $edx
        color_bold
        color_underline
        color $COLOR_CPUFLAGS
    flags
    color_reset
    # ESI
        color $COLOR_REGNAME
    printf "  ESI:"
    if ($esi != $oldesi && $SHOWREGCHANGES == 1)
            color $COLOR_REGVAL_MODIFIED
        else
            color $COLOR_REGVAL
        end
        printf " 0x%08X  ", $esi
        # EDI
        color $COLOR_REGNAME
    printf "EDI:"
        if ($edi != $oldedi && $SHOWREGCHANGES == 1)
            color $COLOR_REGVAL_MODIFIED
        else
            color $COLOR_REGVAL
        end
        printf " 0x%08X  ", $edi
        # EBP
        color $COLOR_REGNAME
        printf "EBP:"
        if ($ebp != $oldebp && $SHOWREGCHANGES == 1)
            color $COLOR_REGVAL_MODIFIED
        else
            color $COLOR_REGVAL
        end
        printf " 0x%08X  ", $ebp
        # ESP
        color $COLOR_REGNAME
    printf "ESP:"
        if ($esp != $oldesp && $SHOWREGCHANGES == 1)
            color $COLOR_REGVAL_MODIFIED
        else
            color $COLOR_REGVAL
    end
    printf " 0x%08X  ", $esp
    # EIP
    color $COLOR_REGNAME
    printf "EIP:"
    color $COLOR_REGVAL_MODIFIED
    printf " 0x%08X\n  ", $eip
    color $COLOR_REGNAME
    printf "CS:"
    color $COLOR_REGVAL
    printf " %04X  ", $cs
    color $COLOR_REGNAME
    printf "DS:"
    color $COLOR_REGVAL
    printf " %04X  ", $ds
    color $COLOR_REGNAME
    printf "ES:"
    color $COLOR_REGVAL
    printf " %04X  ", $es
    color $COLOR_REGNAME
    printf "FS:"
    color $COLOR_REGVAL
    printf " %04X  ", $fs
    color $COLOR_REGNAME
    printf "GS:"
    color $COLOR_REGVAL
    printf " %04X  ", $gs
    color $COLOR_REGNAME
    printf "SS:"
    color $COLOR_REGVAL
    printf " %04X", $ss
    color_reset
end
document regx86
Syntax: regx86
| Auxiliary function to display X86 registers.
end

define reg
    if ($64BITS == 1)
        regx64
    else
        regx86
    end
    # call smallregisters
    smallregisters
    # display conditional jump routine
    if ($64BITS == 1)
            echo \011\011\011\011 	 
    end
    dumpjump
    echo \n
    if ($SHOWREGCHANGES == 1)
        if ($64BITS == 1)
            set $oldrax = $rax
            set $oldrbx = $rbx
            set $oldrcx = $rcx
            set $oldrdx = $rdx
            set $oldrsi = $rsi
            set $oldrdi = $rdi
            set $oldrbp = $rbp
            set $oldrsp = $rsp
            set $oldr8  = $r8
            set $oldr9  = $r9
            set $oldr10 = $r10
            set $oldr11 = $r11
            set $oldr12 = $r12
            set $oldr13 = $r13
            set $oldr14 = $r14
            set $oldr15 = $r15
        else
            set $oldeax = $eax
            set $oldebx = $ebx
            set $oldecx = $ecx
            set $oldedx = $edx
            set $oldesi = $esi
            set $oldedi = $edi
            set $oldebp = $ebp
            set $oldesp = $esp
        end
    end
end
document reg
Syntax: reg
| Print CPU registers.
end


define smallregisters
    if ($64BITS == 1)
    #64bits stuff
        # from rax
        set $eax = $rax & 0xffffffff
        set $ax  = $rax & 0xffff
        set $al  = $ax & 0xff
        set $ah  = $ax >> 8
        # from rbx
        set $ebx = $rbx & 0xffffffff
        set $bx  = $rbx & 0xffff
        set $bl  = $bx & 0xff
        set $bh  = $bx >> 8
            # from rcx
        set $ecx = $rcx & 0xffffffff
        set $cx  = $rcx & 0xffff
        set $cl  = $cx & 0xff
            set $ch  = $cx >> 8
        # from rdx
        set $edx = $rdx & 0xffffffff
        set $dx  = $rdx & 0xffff
        set $dl  = $dx & 0xff
        set $dh  = $dx >> 8
            # from rsi
        set $esi = $rsi & 0xffffffff
        set $si  = $rsi & 0xffff
        # from rdi
        set $edi = $rdi & 0xffffffff
        set $di  = $rdi & 0xffff                
    #32 bits stuff
    else
        # from eax
        set $ax = $eax & 0xffff
        set $al = $ax & 0xff
        set $ah = $ax >> 8
        # from ebx
        set $bx = $ebx & 0xffff
        set $bl = $bx & 0xff
        set $bh = $bx >> 8
        # from ecx
        set $cx = $ecx & 0xffff
        set $cl = $cx & 0xff
        set $ch = $cx >> 8
        # from edx
        set $dx = $edx & 0xffff
        set $dl = $dx & 0xff
        set $dh = $dx >> 8
        # from esi
        set $si = $esi & 0xffff
        # from edi
        set $di = $edi & 0xffff             
     end
end
document smallregisters
Syntax: smallregisters
| Create the 16 and 8 bit cpu registers (gdb doesn't have them by default).
| And 32bits if we are dealing with 64bits binaries.
end


#define func
#    if $argc == 0
#        info functions
#    end
#    if $argc == 1
#        info functions $arg0
#    end
#    if $argc > 1
#        help func
#    end
#end
#document func
#Syntax: func <REGEXP>
#| Print all function names in target, or those matching REGEXP.
#end
#
#
#define var
#    if $argc == 0
#        info variables
#    end
#    if $argc == 1
#        info variables $arg0
#    end
#    if $argc > 1
#        help var
#    end
#end
#document var
#Syntax: var <REGEXP>
#| Print all global and static variable names (symbols), or those matching REGEXP.
#end


#define lib
#    info sharedlibrary
#end
#document lib
#Syntax: lib
#| Print shared libraries linked to target.
#end
#
#
#define sig
#    if $argc == 0
#        info signals
#    end
#    if $argc == 1
#        info signals $arg0
#    end
#    if $argc > 1
#        help sig
#    end
#end
#document sig
#Syntax: sig <SIGNAL>
#| Print what debugger does when program gets various signals.
#| Specify a SIGNAL as argument to print info on that signal only.
#end


#define threads
#    info threads
#end
#document threads
#Syntax: threads
#| Print threads in target.
#end


#define dis
#    if $argc == 0
#        disassemble
#    end
#    if $argc == 1
#        disassemble $arg0
#    end
#    if $argc == 2
#        disassemble $arg0 $arg1
#    end 
#    if $argc > 2
#        help dis
#    end
#end
#document dis
#Syntax: dis <ADDR1> <ADDR2>
#| Disassemble a specified section of memory.
#| Default is to disassemble the function surrounding the PC (program counter) of selected frame. 
#| With one argument, ADDR1, the function surrounding this address is dumped.
#| Two arguments are taken as a range of memory to dump.
#end


# __________hex/ascii dump an address_________
define ascii_char
    if $argc != 1
        help ascii_char
    else
        # thanks elaine :)
        set $_c = *(unsigned char *)($arg0)
        if ($_c < 0x20 || $_c > 0x7E)
            echo .
        else
            printf "%c", $_c
        end
    end
end
document ascii_char
Syntax: ascii_char ADDR
| Print ASCII value of byte at address ADDR.
| Print "." if the value is unprintable.
end


define hex_quad
    if $argc != 1
        help hex_quad
    else
        printf "%02X %02X %02X %02X %02X %02X %02X %02X", \
               *(unsigned char*)($arg0), *(unsigned char*)($arg0 + 1),     \
               *(unsigned char*)($arg0 + 2), *(unsigned char*)($arg0 + 3), \
               *(unsigned char*)($arg0 + 4), *(unsigned char*)($arg0 + 5), \
               *(unsigned char*)($arg0 + 6), *(unsigned char*)($arg0 + 7)
    end
end
document hex_quad
Syntax: hex_quad ADDR
| Print eight hexadecimal bytes starting at address ADDR.
end


define hexdump
    if $argc == 1
        hexdump_aux $arg0
        else
                if $argc == 2
                        set $_count = 0
                        while ($_count < $arg1)
                                set $_i = ($_count * 0x10)
                                hexdump_aux $arg0+$_i
                                set $_count++
                        end
                else
                        help hexdump
                end
    end
end
document hexdump
Syntax: hexdump ADDR <NR_LINES>
| Display a 16-byte hex/ASCII dump of memory starting at address ADDR.
| Optional parameter is the number of lines to display if you want more than one. 
end

define hexdump_aux
    if $argc != 1
        help hexdump_aux
    else
        echo \033[1m
        if ($64BITS == 1)
          printf "0x%016lX : ", $arg0
        else
          printf "0x%08X : ", $arg0
        end
        echo \033[0m
        printf "%02X %02X %02X %02X %02X %02X %02X %02X", \
           *(unsigned char*)($arg0), *(unsigned char*)($arg0 + 1),     \
           *(unsigned char*)($arg0 + 2), *(unsigned char*)($arg0 + 3), \
           *(unsigned char*)($arg0 + 4), *(unsigned char*)($arg0 + 5), \
           *(unsigned char*)($arg0 + 6), *(unsigned char*)($arg0 + 7)
        echo \033[1m\040-\040\033[0m
        printf "%02X %02X %02X %02X %02X %02X %02X %02X", \
           *(unsigned char*)($arg0+8), *(unsigned char*)($arg0+8 + 1),     \
           *(unsigned char*)($arg0+8 + 2), *(unsigned char*)($arg0+8 + 3), \
           *(unsigned char*)($arg0+8 + 4), *(unsigned char*)($arg0+8 + 5), \
           *(unsigned char*)($arg0+8 + 6), *(unsigned char*)($arg0+8 + 7)
        echo \040\033[1m
        ascii_char $arg0+0x0
        ascii_char $arg0+0x1
        ascii_char $arg0+0x2
        ascii_char $arg0+0x3
        ascii_char $arg0+0x4
        ascii_char $arg0+0x5
        ascii_char $arg0+0x6
        ascii_char $arg0+0x7
        ascii_char $arg0+0x8
        ascii_char $arg0+0x9
        ascii_char $arg0+0xA
        ascii_char $arg0+0xB
        ascii_char $arg0+0xC
        ascii_char $arg0+0xD
        ascii_char $arg0+0xE
        ascii_char $arg0+0xF
        echo \033[0m\n
    end
end
document hexdump_aux
Syntax: hexdump_aux ADDR
| Display a 16-byte hex/ASCII dump of memory at address ADDR.
end

## _______________data window__________________
#define ddump
#    if $argc != 1
#        help ddump
#    else
#        color $COLOR_SEPARATOR
#        if ($64BITS == 1)
#            printf "[0x%04X:0x%016lX]", $ds, $data_addr
#        else
#            printf "[0x%04X:0x%08X]", $ds, $data_addr
#        end
#
#        color_bold
#        color $COLOR_SEPARATOR
#        echo --------------------------------------------------------------------------------------------[data]\n
#        color_reset
#        set $_count = 0
#        while ($_count < $arg0)
#            set $_i = ($_count * 0x10)
#            hexdump $data_addr+$_i
#            set $_count++
#        end
#    end
#end
#document ddump
#Syntax: ddump NUM
#| Display NUM lines of hexdump for address in $data_addr global variable.
#end
#
#define dd
#    if $argc != 1
#        help dd
#    else
#        set $data_addr = $arg0
#        ddump 0x10
#    end
#end
#document dd
#Syntax: dd ADDR
#| Display 16 lines of a hex dump of address starting at ADDR.
#end
#
#define datawin
#    if ($64BITS == 1)
#        if ((($rsi >> 0x18) == 0x40) || (($rsi >> 0x18) == 0x08) || (($rsi >> 0x18) == 0xBF))
#            set $data_addr = $rsi
#        else
#        if ((($rdi >> 0x18) == 0x40) || (($rdi >> 0x18) == 0x08) || (($rdi >> 0x18) == 0xBF))
#            set $data_addr = $rdi
#        else
#        if ((($rax >> 0x18) == 0x40) || (($rax >> 0x18) == 0x08) || (($rax >> 0x18) == 0xBF))
#            set $data_addr = $rax
#        else
#            set $data_addr = $rsp
#        end # rsi
#        end # rdi
#        end # rax
#    else
#        if ((($esi >> 0x18) == 0x40) || (($esi >> 0x18) == 0x08) || (($esi >> 0x18) == 0xBF))
#            set $data_addr = $esi
#        else
#        if ((($edi >> 0x18) == 0x40) || (($edi >> 0x18) == 0x08) || (($edi >> 0x18) == 0xBF))
#            set $data_addr = $edi
#        else
#        if ((($eax >> 0x18) == 0x40) || (($eax >> 0x18) == 0x08) || (($eax >> 0x18) == 0xBF))
#            set $data_addr = $eax
#        else
#            set $data_addr = $esp
#        end # esi
#       end # edi
#        end # eax
#    end
#    ddump $CONTEXTSIZE_DATA
#end
#document datawin
#Syntax: datawin
#| Display valid address from one register in data window.
#end

# Huge mess going here :) HAHA
define dumpjump
    ## grab the first two bytes from the instruction so we can determine the jump instruction
    set $_byte1 = *(unsigned char *)$pc
    set $_byte2 = *(unsigned char *)($pc+1)
    ## and now check what kind of jump we have (in case it's a jump instruction)
    ## I changed the flags routine to save the flag into a variable, so we don't need to repeat the process :) (search for "define flags")

    ## opcode 0x77: JA, JNBE (jump if CF=0 and ZF=0)
    ## opcode 0x0F87: JNBE, JA
    if ( ($_byte1 == 0x77) || ($_byte1 == 0x0F && $_byte2 == 0x87) )
            # cf=0 and zf=0
            if ($_cf_flag == 0 && $_zf_flag == 0)
                    color $RED
                    printf "  Jump is taken (c=0 and z=0)"
            else
            # cf != 0 or zf != 0
                    color $RED
                    printf "  Jump is NOT taken (c!=0 or z!=0)"
            end 
    end
    ## opcode 0x73: JAE, JNB, JNC (jump if CF=0)
    ## opcode 0x0F83: JNC, JNB, JAE (jump if CF=0)
    if ( ($_byte1 == 0x73) || ($_byte1 == 0x0F && $_byte2 == 0x83) )
            # cf=0
            if ($_cf_flag == 0)
                    color $RED
                    printf "  Jump is taken (c=0)"
            else
            # cf != 0
                    color $RED
                    printf "  Jump is NOT taken (c!=0)"
            end 
    end
    ## opcode 0x72: JB, JC, JNAE (jump if CF=1)
    ## opcode 0x0F82: JNAE, JB, JC
    if ( ($_byte1 == 0x72) || ($_byte1 == 0x0F && $_byte2 == 0x82) )
        # cf=1
            if ($_cf_flag == 1)
                    color $RED
                    printf "  Jump is taken (c=1)"
            else
            # cf != 1
                    color $RED
                    printf "  Jump is NOT taken (c!=1)"
            end 
    end
    ## opcode 0x76: JBE, JNA (jump if CF=1 or ZF=1)
    ## opcode 0x0F86: JBE, JNA
    if ( ($_byte1 == 0x76) || ($_byte1 == 0x0F && $_byte2 == 0x86) )
            # cf=1 or zf=1
            if (($_cf_flag == 1) || ($_zf_flag == 1))
                    color $RED
                    printf "  Jump is taken (c=1 or z=1)"
            else
            # cf != 1 or zf != 1
                    color $RED
                    printf "  Jump is NOT taken (c!=1 or z!=1)"
            end 
    end
    ## opcode 0xE3: JCXZ, JECXZ, JRCXZ (jump if CX=0 or ECX=0 or RCX=0)
    if ($_byte1 == 0xE3)
            # cx=0 or ecx=0
            if (($ecx == 0) || ($cx == 0))
                    color $RED
                    printf "  Jump is taken (cx=0 or ecx=0)"
            else
                color $RED
            printf "  Jump is NOT taken (cx!=0 or ecx!=0)"
            end 
    end
    ## opcode 0x74: JE, JZ (jump if ZF=1)
    ## opcode 0x0F84: JZ, JE, JZ (jump if ZF=1)
    if ( ($_byte1 == 0x74) || ($_byte1 == 0x0F && $_byte2 == 0x84) )
         # ZF = 1
            if ($_zf_flag == 1)
                    color $RED
                    printf "  Jump is taken (z=1)"
            else
            # ZF = 0
                    color $RED
                    printf "  Jump is NOT taken (z!=1)"
            end 
    end
    ## opcode 0x7F: JG, JNLE (jump if ZF=0 and SF=OF)
    ## opcode 0x0F8F: JNLE, JG (jump if ZF=0 and SF=OF)
    if ( ($_byte1 == 0x7F) || ($_byte1 == 0x0F && $_byte2 == 0x8F) )
        # zf = 0 and sf = of
            if (($_zf_flag == 0) && ($_sf_flag == $_of_flag))
                    color $RED
                    printf "  Jump is taken (z=0 and s=o)"
            else
                    color $RED
                    printf "  Jump is NOT taken (z!=0 or s!=o)"
            end 
    end
    ## opcode 0x7D: JGE, JNL (jump if SF=OF)
    ## opcode 0x0F8D: JNL, JGE (jump if SF=OF)
    if ( ($_byte1 == 0x7D) || ($_byte1 == 0x0F && $_byte2 == 0x8D) )
        # sf = of
            if ($_sf_flag == $_of_flag)
                    color $RED
                    printf "  Jump is taken (s=o)"
            else
                    color $RED
                    printf "  Jump is NOT taken (s!=o)"
            end 
    end
    ## opcode: 0x7C: JL, JNGE (jump if SF != OF)
    ## opcode: 0x0F8C: JNGE, JL (jump if SF != OF)
    if ( ($_byte1 == 0x7C) || ($_byte1 == 0x0F && $_byte2 == 0x8C) )
        # sf != of
            if ($_sf_flag != $_of_flag)
                    color $RED
                    printf "  Jump is taken (s!=o)"
            else
                    color $RED
                    printf "  Jump is NOT taken (s=o)"
            end 
    end
    ## opcode 0x7E: JLE, JNG (jump if ZF = 1 or SF != OF)
    ## opcode 0x0F8E: JNG, JLE (jump if ZF = 1 or SF != OF)
    if ( ($_byte1 == 0x7E) || ($_byte1 == 0x0F && $_byte2 == 0x8E) )
        # zf = 1 or sf != of
            if (($_zf_flag == 1) || ($_sf_flag != $_of_flag))
                    color $RED
                    printf "  Jump is taken (zf=1 or sf!=of)"
            else
                    color $RED
                    printf "  Jump is NOT taken (zf!=1 or sf=of)"
            end 
    end
    ## opcode 0x75: JNE, JNZ (jump if ZF = 0)
    ## opcode 0x0F85: JNE, JNZ (jump if ZF = 0)
    if ( ($_byte1 == 0x75) || ($_byte1 == 0x0F && $_byte2 == 0x85) )
        # ZF = 0
            if ($_zf_flag == 0)
                    color $RED
                    printf "  Jump is taken (z=0)"
            else
            # ZF = 1
                    color $RED
                    printf "  Jump is NOT taken (z!=0)"
            end 
    end
    ## opcode 0x71: JNO (OF = 0)
    ## opcode 0x0F81: JNO (OF = 0)
    if ( ($_byte1 == 0x71) || ($_byte1 == 0x0F && $_byte2 == 0x81) )
        # OF = 0
            if ($_of_flag == 0)
                    color $RED
                    printf "  Jump is taken (o=0)"
            else
            # OF != 0
                    color $RED
                    printf "  Jump is NOT taken (o!=0)"
            end 
    end
    ## opcode 0x7B: JNP, JPO (jump if PF = 0)
    ## opcode 0x0F8B: JPO (jump if PF = 0)
    if ( ($_byte1 == 0x7B) || ($_byte1 == 0x0F && $_byte2 == 0x8B) )
         # PF = 0
            if ($_pf_flag == 0)
                    color $RED
                    printf "  Jump is NOT taken (p=0)"
            else
            # PF != 0
                    color $RED
                    printf "  Jump is taken (p!=0)"
            end 
    end
    ## opcode 0x79: JNS (jump if SF = 0)
    ## opcode 0x0F89: JNS (jump if SF = 0)
    if ( ($_byte1 == 0x79) || ($_byte1 == 0x0F && $_byte2 == 0x89) )
         # SF = 0
            if ($_sf_flag == 0)
                    color $RED
                    printf "  Jump is taken (s=0)"
            else
             # SF != 0
                    color $RED
                    printf "  Jump is NOT taken (s!=0)"
            end 
    end
    ## opcode 0x70: JO (jump if OF=1)
    ## opcode 0x0F80: JO (jump if OF=1)
    if ( ($_byte1 == 0x70) || ($_byte1 == 0x0F && $_byte2 == 0x80) )
         # OF = 1
            if ($_of_flag == 1)
                    color $RED
                    printf "  Jump is taken (o=1)"
            else
            # OF != 1
                    color $RED
                    printf "  Jump is NOT taken (o!=1)"
            end 
    end
    ## opcode 0x7A: JP, JPE (jump if PF=1)
    ## opcode 0x0F8A: JP, JPE (jump if PF=1)
    if ( ($_byte1 == 0x7A) || ($_byte1 == 0x0F && $_byte2 == 0x8A) )
        # PF = 1
            if ($_pf_flag == 1)
                    color $RED
                    printf "  Jump is taken (p=1)"
            else
             # PF = 0
                    color $RED
                    printf "  Jump is NOT taken (p!=1)"
            end 
    end
    ## opcode 0x78: JS (jump if SF=1)
    ## opcode 0x0F88: JS (jump if SF=1)
    if ( ($_byte1 == 0x78) || ($_byte1 == 0x0F && $_byte2 == 0x88) )
           # SF = 1
            if ($_sf_flag == 1)
                    color $RED
                    printf "  Jump is taken (s=1)"
            else
             # SF != 1
                    color $RED
                    printf "  Jump is NOT taken (s!=1)"
            end 
    end
end
document dumpjump
Syntax: dumpjump
| Display if conditional jump will be taken or not.
end

define dumpjumphelper
    # 0000 - EQ: Z == 1
    if ($_conditional == 0x0)
            if ($_z_flag == 1)
                    color $RED
                printf " Jump is taken (z==1)"
        else
                color $RED
                printf " Jump is NOT taken (z!=1)"
        end
    end
    # 0001 - NE: Z == 0
    if ($_conditional == 0x1)
            if ($_z_flag == 0)
                    color $RED
                printf " Jump is taken (z==0)"
            else
                    color $RED
                printf " Jump is NOT taken (z!=0)"
            end
    end
    # 0010 - CS: C == 1
    if ($_conditional == 0x2)
            if ($_c_flag == 1)
                    color $RED
                printf " Jump is taken (c==1)"
            else
                    color $RED
                printf " Jump is NOT taken (c!=1)"
            end
    end
    # 0011 - CC: C == 0
    if ($_conditional == 0x3)
            if ($_c_flag == 0)
                    color $RED
                printf " Jump is taken (c==0)"
            else
                    color $RED
                printf " Jump is NOT taken (c!=0)"
            end
    end
    # 0100 - MI: N == 1
    if ($_conditional == 0x4)
            if ($_n_flag == 1)
                    color $RED
                printf " Jump is taken (n==1)"
        else
                    color $RED
                printf " Jump is NOT taken (n!=1)"
            end
    end
    # 0101 - PL: N == 0
    if ($_conditional == 0x5)
            if ($_n_flag == 0)
                    color $RED
                printf " Jump is taken (n==0)"
            else
                    color $RED
                printf " Jump is NOT taken (n!=0)"
            end
    end
    # 0110 - VS: V == 1
    if ($_conditional == 0x6)
            if ($_v_flag == 1)
                    color $RED
                printf " Jump is taken (v==1)"
            else
                    color $RED
                printf " Jump is NOT taken (v!=1)"
            end
    end
    # 0111 - VC: V == 0
    if ($_conditional == 0x7)
            if ($_v_flag == 0)
                    color $RED
                printf " Jump is taken (v==0)"
        else
                color $RED
                printf " Jump is NOT taken (v!=0)"
            end
    end
    # 1000 - HI: C == 1 and Z == 0
    if ($_conditional == 0x8)
            if ($_c_flag == 1 && $_z_flag == 0)
                    color $RED
                printf " Jump is taken (c==1 and z==0)"
        else
                color $RED
                printf " Jump is NOT taken (c!=1 or z!=0)"
        end
    end
    # 1001 - LS: C == 0 or Z == 1
    if ($_conditional == 0x9)
            if ($_c_flag == 0 || $_z_flag == 1)
                    color $RED
                printf " Jump is taken (c==0 or z==1)"
            else
                color $RED
                printf " Jump is NOT taken (c!=0 or z!=1)"
            end
    end
    # 1010 - GE: N == V
    if ($_conditional == 0xA)
            if ($_n_flag == $_v_flag)
                    color $RED
                printf " Jump is taken (n==v)"
        else
                color $RED
                printf " Jump is NOT taken (n!=v)"
        end
    end
    # 1011 - LT: N != V
    if ($_conditional == 0xB)
            if ($_n_flag != $_v_flag)
                    color $RED
                printf " Jump is taken (n!=v)"
            else
                    color $RED
                printf " Jump is NOT taken (n==v)"
            end
    end
    # 1100 - GT: Z == 0 and N == V
    if ($_conditional == 0xC)
            if ($_z_flag == 0 && $_n_flag == $_v_flag)
                    color $RED
                printf " Jump is taken (z==0 and n==v)"
            else
                    color $RED
                printf " Jump is NOT taken (z!=0 or n!=v)"
            end
    end
    # 1101 - LE: Z == 1 or N != V
    if ($_conditional == 0xD)
            if ($_z_flag == 1 || $_n_flag != $_v_flag)
                    color $RED
                printf " Jump is taken (z==1 or n!=v)"
            else
                    color $RED
                printf " Jump is NOT taken (z!=1 or n==v)"
            end
    end
end
document dumpjumphelper
Syntax: dumpjumphelper
| Helper function to decide if conditional jump will be taken or not.
end


# _______________process context______________
# initialize variable
set $displayobjectivec = 0

define context 
    if $SHOWCPUREGISTERS == 1
        color $COLOR_SEPARATOR
        color_bold
        echo ------------------------------------------------------------------------------------------------------[registers]\n
        color_reset
        reg
    end
    if $SHOWSTACK == 1
        color $COLOR_SEPARATOR
        color_bold
        printf "[0x%08X]", $sp
        if ($64BITS == 1)
            printf "[0x%04X:0x%016lX]", $ss, $rsp
        else
            printf "[0x%04X:0x%08X]", $ss, $esp
        end
        echo -------------------------------------------------------------------[stack]\n
        color_reset
        set $context_idx = $CONTEXTSIZE_STACK
        while ($context_idx > 0)
            set     $context_t = $sp + 0x10 * ($context_idx - 1)
            hexdump $context_t
            set     $context_idx--
        end
    end
    if $SHOWDATAWIN == 1
        datawin
    end
    color $COLOR_SEPARATOR
    color_bold
    echo -----------------------------------------------------------------------------------------------------------[text]\n
    color_reset
    color $GREEN
    set $context_idx = $CONTEXTSIZE_CODE
    if ($context_idx > 0)
        x/i $pc
        set $context_idx--
    end
    color_reset
    while ($context_idx > 0)
        x /i
        set $context_idx--
    end
    # Run "list"
    color $COLOR_SEPARATOR
    color_bold
    echo -----------------------------------------------------------------------------------------------------------[list]
    color_reset
    list
    # Separator
    color $COLOR_SEPARATOR
    color_bold
    echo -----------------------------------------------------------------------------------------------------------------\n
    color_reset
end
document context
Syntax: context
| Print context window, i.e. regs, stack, ds:esi and disassemble cs:eip.
end


define context-on
    set $SHOW_CONTEXT = 1
    printf "Displaying of context is now ON\n"
end
document context-on
Syntax: context-on
| Enable display of context on every program break.
end


define context-off
    set $SHOW_CONTEXT = 0
    printf "Displaying of context is now OFF\n"
end
document context-off
Syntax: context-off
| Disable display of context on every program break.
end


# _______________process control______________
#define n
#    if $argc == 0
#        nexti
#    end
#    if $argc == 1
#        nexti $arg0
#    end
#    if $argc > 1
#        help n
#    end
#end
#document n
#Syntax: n <NUM>
#| Step one instruction, but proceed through subroutine calls.
#| If NUM is given, then repeat it NUM times or till program stops.
#| This is alias for nexti.
#end


define go
    if $argc == 0
        stepi
    end
    if $argc == 1
        stepi $arg0
    end
    if $argc > 1
        help go
    end
end
document go
Syntax: go <NUM>
| Step one instruction exactly.
| If NUM is given, then repeat it NUM times or till program stops.
| This is alias for stepi.
end


define pret
    finish
end
document pret
Syntax: pret
| Execute until selected stack frame returns (step out of current call).
| Upon return, the value returned is printed and put in the value history.
end


define init
    set $SHOW_NEST_INSN = 0
    tbreak _init
    r
end
document init
Syntax: init
| Run program and break on _init().
end


define start
    set $SHOW_NEST_INSN = 0
    tbreak _start
    r
end
document start
Syntax: start
| Run program and break on _start().
end


define sstart
    set $SHOW_NEST_INSN = 0
    tbreak __libc_start_main
    r
end
document sstart
Syntax: sstart
| Run program and break on __libc_start_main().
| Useful for stripped executables.
end


define main
    set $SHOW_NEST_INSN = 0
    tbreak main
    r
end
document main
Syntax: main
| Run program and break on main().
end

# ____________________patch___________________
define nop
    if ($argc > 2 || $argc == 0)
        help nop
    end
    if ($argc == 1)
        set *(unsigned char *)$arg0 = 0x90
    else
        set $addr = $arg0
        while ($addr < $arg1)
            set *(unsigned char *)$addr = 0x90
            set $addr = $addr + 1
        end
    end
end
document nop
Syntax: nop ADDR1 [ADDR2]
| Patch a single byte at address ADDR1, or a series of bytes between ADDR1 and ADDR2 to a NOP (0x90) instruction.
end


define null
    if ( $argc >2 || $argc == 0)
        help null
    end
 
    if ($argc == 1)
            set *(unsigned char *)$arg0 = 0
    else
            set $addr = $arg0
        while ($addr < $arg1)
                set *(unsigned char *)$addr = 0
                    set $addr = $addr +1
            end
    end
end
document null
Syntax: null ADDR1 [ADDR2]
| Patch a single byte at address ADDR1 to NULL (0x00), or a series of bytes between ADDR1 and ADDR2.
end

# FIXME: thumb breakpoint ?
define int3
    if $argc != 1
        help int3
    else
        # save original bytes and address
        set $ORIGINAL_INT3 = *(unsigned char *)$arg0
        set $ORIGINAL_INT3ADDRESS = $arg0
        # patch
        set *(unsigned char *)$arg0 = 0xCC
    end
end
document int3
Syntax int3 ADDR
| Patch byte at address ADDR to an INT3 (0xCC) instruction
end


define rint3
    set *(unsigned char *)$ORIGINAL_INT3ADDRESS = $ORIGINAL_INT3
    if ($64BITS == 1)
        set $rip = $ORIGINAL_INT3ADDRESS
    else
        set $eip = $ORIGINAL_INT3ADDRESS
    end
end
document rint3
Syntax: rint3
| Restore the original byte previous to int3 patch issued with "int3" command.
end

define patch
    if $argc != 3
        help patch
    end
    set $patchaddr = $arg0
    set $patchbytes = $arg1
    set $patchsize = $arg2

    if ($patchsize == 1)
        set *(unsigned char*)$patchaddr = $patchbytes
    end
    if ($patchsize == 2)
        set $lendianbytes = (unsigned short)(($patchbytes << 8) | ($patchbytes >> 8))
        set *(unsigned short*)$patchaddr = $lendianbytes
    end
    if ($patchsize == 4)
        set $lendianbytes = (unsigned int)( (($patchbytes << 8) & 0xFF00FF00 ) | (($patchbytes >> 8) & 0xFF00FF ))
        set $lendianbytes = (unsigned int)($lendianbytes << 0x10 | $lendianbytes >> 0x10)
        set *(unsigned int*)$patchaddr = $lendianbytes
    end
    if ($patchsize == 8)
        set $lendianbytes = (unsigned long long)( (($patchbytes << 8) & 0xFF00FF00FF00FF00ULL ) | (($patchbytes >> 8) & 0x00FF00FF00FF00FFULL ) )
        set $lendianbytes = (unsigned long long)( (($lendianbytes << 0x10) & 0xFFFF0000FFFF0000ULL ) | (($lendianbytes >> 0x10) & 0x0000FFFF0000FFFFULL ) )
        set $lendianbytes = (unsigned long long)( ($lendianbytes << 0x20) | ($lendianbytes >> 0x20) )
        set *(unsigned long long*)$patchaddr = $lendianbytes
    end
end
document patch
Syntax: patch address bytes size
| Patch a given address, converting the bytes to little-endian.
| Assumes input bytes are unsigned values and should be in hexadecimal format (0x...).
| Size must be 1, 2, 4, 8 bytes.
| Main purpose is to be used with the output from the asm commands.
end

# ____________________cflow___________________
define print_insn_type
  if ($arg0 < 0 || $arg0 > 5)
    echo ERROR/INVALID
  else
  if ($arg0 == 0)
    echo UNKNOWN
  else
  if ($arg0 == 1)
    echo JMP
  else
  if ($arg0 == 2)
    echo JCC
  else
  if ($arg0 == 3)
    echo CALL
  else
  if ($arg0 == 4)
    echo RET
  else
  if ($arg0 == 5)
    echo INT
  end
  end
  end
  end
  end
  end 
  end
end
document print_insn_type
Syntax: print_insn_type INSN_TYPE_NUMBER
| Print human-readable mnemonic for the instruction type (usually $INSN_TYPE).
end


# XXX This is crap. Simply rearanging the conditions to only check a range of values once would
#     be quicker. 
# 
# XXX Doesn't matter though. I would rather see this translated too python and driven by a state machine. 
define get_insn_type
  # INVALID 
  set $INSN_TYPE = 0
  set $_byte1 = *(unsigned char*)$arg0
  # CALL
  if ($_byte1 == 0x9A || $_byte1 == 0xE8)
    set $INSN_TYPE = 3
  else
  # JMP
  if ($_byte1 >= 0xE9 && $_byte1 <= 0xEB)
    set $INSN_TYPE = 1
  else
  # JCC
  if ($_byte1 >= 0x70 && $_byte1 <= 0x7F)
    set $INSN_TYPE = 2
  else
  # JCC
  # XXX This can probably be tucked beneath the above expression. 
  if ($_byte1 >= 0xE0 && $_byte1 <= 0xE3)
    set $INSN_TYPE = 2
  else
  # RET
  if ($_byte1 == 0xC2 || $_byte1 == 0xC3 || $_byte1 == 0xCA || $_byte1 == 0xCB || $_byte1 == 0xCF)
    set $INSN_TYPE = 4
  else
  # INT
  if ($_byte1 >= 0xCC && $_byte1 <= 0xCE)
    set $INSN_TYPE = 5
  else
  # Two-byte OPCODE
  if ($_byte1 == 0x0F)
    set $_byte2 = *(unsigned char*)($arg0 + 1)
    # "jcc"
    if ($_byte2 >= 0x80 && $_byte2 <= 0x8F)
      set $INSN_TYPE = 2
    end
  else
  # OPCODE Extension
  if ($_byte1 == 0xFF)        
    set $_byte2 = *(unsigned char*)($arg0 + 1)
    set $_opext = ($_byte2 & 0x38)
    # CALL
    if ($_opext == 0x10 || $_opext == 0x18) 
      set $INSN_TYPE = 3
    end
    # JMP
    if ($_opext == 0x20 || $_opext == 0x28)
      set $INSN_TYPE = 1
    end
  end
  # XXX Moved from each expression above. Replaced with "else\rif" which should be faster.
  end
  end
  end
  end
  end
  end
  end
end
document get_insn_type
Syntax: get_insn_type ADDR
| Recognize instruction type at address ADDR.
| Take address ADDR and set the global $INSN_TYPE variable to
| 0, 1, 2, 3, 4, 5 if the instruction at that address is
| unknown, a jump, a conditional jump, a call, a return, or an interrupt.
end


define step_to_call
    set $_saved_ctx = $SHOW_CONTEXT
    set $SHOW_CONTEXT = 0
    set $SHOW_NEST_INSN = 0
    set logging file /dev/null
    set logging redirect on
    set logging on
    set $_cont = 1
    while ($_cont > 0)
        stepi
        get_insn_type $pc
        if ($INSN_TYPE == 3)
            set $_cont = 0
        end
    end
    set logging off
    if ($_saved_ctx > 0)
        context
    end
    set $SHOW_CONTEXT = $_saved_ctx
    set $SHOW_NEST_INSN = 0
    set logging file ~/gdb.txt
    set logging redirect off
    set logging on
    echo step_to_call command stopped at:\n 
    x/i $pc
    echo \n
    set logging off

end
document step_to_call
Syntax: step_to_call
| Single step until a call instruction is found.
| Stop before the call is taken.
| Log is written into the file ~/gdb.txt.
end

#
# TRACE_CALLS
# 
#   TODO: GDB Sucks, however this logic is not great either.
#         Fix this crap to be more quick.
# 
#
define trace_calls
  echo Trace in progress! This could take a short lifetime so be patient.\n
  set $_saved_ctx = $SHOW_CONTEXT
  set $SHOW_CONTEXT   = 0
  set $SHOW_NEST_INSN = 0
  set $_nest          = 1
  set listsize 0
  set logging overwrite on
  set logging file ~/gdb_trace_calls.txt
  set logging on
  set logging off
  set logging overwrite off
  while ($_nest > 0)
    get_insn_type $pc
    if ($INSN_TYPE == 4)
      set $_nest = $_nest - 1
    else
      if ($INSN_TYPE == 3)
        set $_nest = $_nest + 1
        set logging file ~/gdb_trace_calls.txt
        set logging redirect off
        set logging on
        set $x = $_nest - 2
        if ($x > 0)
          while ($x >= 4)
            echo \040\040\040\040\040\040\040
            set $x = $x - 4
          end
          while ($x >= 2)
            echo \040\040\040\040
            set $x = $x - 2
          end
          while ($x > 0)
            echo \040\040
            set $x = $x - 1
          end
        end
        x/i $pc
      end
      # if 
    end
    # if/else
    set logging off
    set logging file /dev/null
    set logging redirect on
    set logging on
    stepi
    set logging redirect off
    set logging off
  end
  # while
  set $SHOW_CONTEXT = $_saved_ctx
  set $SHOW_NEST_INSN = 0
  set listsize 10
  echo Done! Results saved in "~/gdb_trace_calls.txt"\n
end
document trace_calls
Syntax: trace_calls
| Create a runtime trace of the calls made by target.
| Log overwrites(!) the file ~/gdb_trace_calls.txt.
end

define trace_run
    printf "Tracing...please wait...\n"
    set $_saved_ctx = $SHOW_CONTEXT
    set $SHOW_CONTEXT = 0
    set $SHOW_NEST_INSN = 1
    set logging overwrite on
    set logging file ~/gdb_trace_run.txt
    set logging redirect on
    set logging on
    set $_nest = 1
    while ( $_nest > 0 )
        get_insn_type $pc
        # jmp, jcc, or cll
        if ($INSN_TYPE == 3)
            set $_nest = $_nest + 1
        else
            # ret
            if ($INSN_TYPE == 4)
                set $_nest = $_nest - 1
            end
        end
        stepi
    end
    echo \n
    set $SHOW_CONTEXT = $_saved_ctx
    set $SHOW_NEST_INSN = 0
    set logging redirect off
    set logging off
    # clean up trace file
    shell  grep -v ' at ' ~/gdb_trace_run.txt > ~/gdb_trace_run.1
    shell  grep -v ' in ' ~/gdb_trace_run.1 > ~/gdb_trace_run.txt
    shell  rm -f ~/gdb_trace_run.1
    printf "Done, check ~/gdb_trace_run.txt\n"
end
document trace_run
Syntax: trace_run
| Create a runtime trace of target.
| Log overwrites(!) the file ~/gdb_trace_run.txt.
end

define entry_point
    set logging redirect on
    set logging file /tmp/gdb-entry_point
    set logging on
    info files
    set logging off
    shell entry_point="$(/usr/bin/grep 'Entry point:' /tmp/gdb-entry_point | /usr/bin/awk '{ print $3 }')"; echo "$entry_point"; echo 'set $entry_point_address = '"$entry_point" > /tmp/gdb-entry_point
    source /tmp/gdb-entry_point
    shell /bin/rm -f /tmp/gdb-entry_point
end
document entry_point
Syntax: entry_point
| Prints the entry point address of the target and stores it in the variable entry_point.
end

define break_entrypoint
  entry_point
  break *$entry_point_address
end
document break_entrypoint
Syntax: break_entrypoint
| Sets a breakpoint on the entry point of the target.
end

# ____________________misc____________________
#shell [ -e /tmp/colorPipe ] && rm -f /tmp/colorPipe
#shell mkfifo /tmp/colorPipe
#define hook-disassemble
#  echo \n
#  shell cat /tmp/colorPipe | c++filt | highlight --syntax=asm -s darkness -Oxterm256 &
#  set logging redirect on
#  set logging on /tmp/colorPipe
#end
#document hook-disassemble
#| !!! Internal
#end
#
#define hookpost-disassemble
# hookpost-list
#end
#document hookpost-disassemble
#| !!! Internal
#end
#
#hdefine hook-list
#h  echo \n
#h  shell cat /tmp/colorPipe | c++filt | highlight --syntax=cpp -s darkness -Oxterm256 &
#h  set logging redirect on
#h  set logging on /tmp/colorPipe
#hend
#document hook-list
#| !!! Internal
#end

#define hookpost-list
#  set logging off
#  set logging redirect off
#  shell sleep 0.1s
#end
#document hookpost-list
#| !!! Internal
#end
#
define hook-stop
  if (sizeof(void*) == 8)
    set $64BITS = 1
  else
    set $64BITS = 0
  end
  if ($SHOW_CONTEXT > 0)
      context
  end
  if ($SHOW_NEST_INSN > 0)
    set $x = $_nest
    while ($x > 0)
      echo \040\040
      set $x = $x - 1
    end
  end
end
document hook-stop
Syntax: hook-stop
| !!! FOR INTERNAL USE ONLY - DO NOT CALL !!!
end

# original by Tavis Ormandy (http://my.opera.com/taviso/blog/index.dml/tag/gdb) (great fix!)
# modified to work with Mac OS X by fG!
# seems nasm shipping with Mac OS X has problems accepting input from stdin or heredoc
# input is read into a variable and sent to a temporary file which nasm can read
#define assemble
#    # dont enter routine again if user hits enter
#    dont-repeat
#    if ($argc)
#        if (*$arg0 = *$arg0)
#        # check if we have a valid address by dereferencing it,
#        # if we havnt, this will cause the routine to exit.
#        end
#        printf "Instructions will be written to %#x.\n", $arg0
#    else
#        printf "Instructions will be written to stdout.\n"
#    end
#    printf "Type instructions, one per line."
#        color_bold
#    printf " Do not forget to use NASM assembler syntax!\n"
#    color_reset
#    printf "End with a line saying just \"end\".\n"
#    
#    if ($argc)
#            if ($64BITS == 1)
#                    # argument specified, assemble instructions into memory at address specified.
#                shell ASMOPCODE="$(while read -ep '>' r && test "$r" != end ; do echo -E "$r"; done)" ; GDBASMFILENAME=$RANDOM; \
#                echo -e "BITS 64\n$ASMOPCODE" >/tmp/$GDBASMFILENAME ; /usr/local/bin/nasm -f bin -o /dev/stdout /tmp/$GDBASMFILENAME | /usr/bin/hexdump -ve '1/1 "set *((unsigned char *) $arg0 + %#2_ax) = %#02x\n"' >/tmp/gdbassemble ; /bin/rm -f /tmp/$GDBASMFILENAME
#                source /tmp/gdbassemble
#                # all done. clean the temporary file
#                shell /bin/rm -f /tmp/gdbassemble
#        else
#                # argument specified, assemble instructions into memory at address specified.
#                shell ASMOPCODE="$(while read -ep '>' r && test "$r" != end ; do echo -E "$r"; done)" ; GDBASMFILENAME=$RANDOM; \
#                    echo -e "BITS 32\n$ASMOPCODE" >/tmp/$GDBASMFILENAME ; /usr/bin/nasm -f bin -o /dev/stdout /tmp/$GDBASMFILENAME | /usr/bin/hexdump -ve '1/1 "set *((unsigned char *) $arg0 + %#2_ax) = %#02x\n"' >/tmp/gdbassemble ; /bin/rm -f /tmp/$GDBASMFILENAME
#                source /tmp/gdbassemble
#                # all done. clean the temporary file
#                    shell /bin/rm -f /tmp/gdbassemble
#        end
#    else
#            if ($64BITS == 1)
#                    # no argument, assemble instructions to stdout
#                shell ASMOPCODE="$(while read -ep '>' r && test "$r" != end ; do echo -E "$r"; done)" ; GDBASMFILENAME=$RANDOM; \
#                echo -e "BITS 64\n$ASMOPCODE" >/tmp/$GDBASMFILENAME ; /usr/local/bin/nasm -f bin -o /dev/stdout /tmp/$GDBASMFILENAME | /usr/local/bin/ndisasm -i -b64 /dev/stdin ; \
#                    /bin/rm -f /tmp/$GDBASMFILENAME
#        else
#                # no argument, assemble instructions to stdout
#                shell ASMOPCODE="$(while read -ep '>' r && test "$r" != end ; do echo -E "$r"; done)" ; GDBASMFILENAME=$RANDOM; \
#                echo -e "BITS 32\n$ASMOPCODE" >/tmp/$GDBASMFILENAME ; /usr/bin/nasm -f bin -o /dev/stdout /tmp/$GDBASMFILENAME | /usr/bin/ndisasm -i -b32 /dev/stdin ; \
#                    /bin/rm -f /tmp/$GDBASMFILENAME
#        end
#    end
#end
#document assemble
#Syntax: assemble <ADDR>
#| Assemble instructions using nasm.
#| Type a line containing "end" to indicate the end.
#| If an address is specified, insert/modify instructions at that address.
#| If no address is specified, assembled instructions are printed to stdout.
#| Use the pseudo instruction "org ADDR" to set the base address.
#end
#
#define assemble32
#    # dont enter routine again if user hits enter
#    dont-repeat
#    if ($argc)
#        if (*$arg0 = *$arg0)
#        # check if we have a valid address by dereferencing it,
#        # if we havnt, this will cause the routine to exit.
#        end
#        printf "Instructions will be written to %#x.\n", $arg0
#    else
#        printf "Instructions will be written to stdout.\n"
#    end
#    printf "Type instructions, one per line."
#    color_bold
#    printf " Do not forget to use NASM assembler syntax!\n"
#    color_reset
#    printf "End with a line saying just \"end\".\n"
#    
#    if ($argc)
#        # argument specified, assemble instructions into memory at address specified.
#        shell ASMOPCODE="$(while read -ep '>' r && test "$r" != end ; do echo -E "$r"; done)" ; GDBASMFILENAME=$RANDOM; \
#        echo -e "BITS 32\n$ASMOPCODE" >/tmp/$GDBASMFILENAME ; /usr/bin/nasm -f bin -o /dev/stdout /tmp/$GDBASMFILENAME | /usr/bin/hexdump -ve '1/1 "set *((unsigned char *) $arg0 + %#2_ax) = %#02x\n"' >/tmp/gdbassemble ; /bin/rm -f /tmp/$GDBASMFILENAME
#        source /tmp/gdbassemble
#        # all done. clean the temporary file
#        shell /bin/rm -f /tmp/gdbassemble
#    else
#        # no argument, assemble instructions to stdout
#        shell ASMOPCODE="$(while read -ep '>' r && test "$r" != end ; do echo -E "$r"; done)" ; GDBASMFILENAME=$RANDOM; \
#        echo -e "BITS 32\n$ASMOPCODE" >/tmp/$GDBASMFILENAME ; /usr/bin/nasm -f bin -o /dev/stdout /tmp/$GDBASMFILENAME | /usr/bin/ndisasm -i -b32 /dev/stdin ; \
#        /bin/rm -f /tmp/$GDBASMFILENAME
#    end
#end
#document assemble32
#Syntax: assemble32 <ADDR>
#| Assemble 32 bits instructions using nasm.
#| Type a line containing "end" to indicate the end.
#| If an address is specified, insert/modify instructions at that address.
#| If no address is specified, assembled instructions are printed to stdout.
#| Use the pseudo instruction "org ADDR" to set the base address.
#end
#
#define assemble64
#    # dont enter routine again if user hits enter
#    dont-repeat
#    if ($argc)
#        if (*$arg0 = *$arg0)
#        # check if we have a valid address by dereferencing it,
#        # if we havnt, this will cause the routine to exit.
#        end
#        printf "Instructions will be written to %#x.\n", $arg0
#    else
#        printf "Instructions will be written to stdout.\n"
#    end
#    printf "Type instructions, one per line."
#    color_bold
#    printf " Do not forget to use NASM assembler syntax!\n"
#    color_reset
#    printf "End with a line saying just \"end\".\n"
#    
#    if ($argc)
#        # argument specified, assemble instructions into memory at address specified.
#        shell ASMOPCODE="$(while read -ep '>' r && test "$r" != end ; do echo -E "$r"; done)" ; GDBASMFILENAME=$RANDOM; \
#        echo -e "BITS 64\n$ASMOPCODE" >/tmp/$GDBASMFILENAME ; /usr/local/bin/nasm -f bin -o /dev/stdout /tmp/$GDBASMFILENAME | /usr/bin/hexdump -ve '1/1 "set *((unsigned char *) $arg0 + %#2_ax) = %#02x\n"' >/tmp/gdbassemble ; /bin/rm -f /tmp/$GDBASMFILENAME
#        source /tmp/gdbassemble
#        # all done. clean the temporary file
#        shell /bin/rm -f /tmp/gdbassemble
#    else
#        # no argument, assemble instructions to stdout
#        shell ASMOPCODE="$(while read -ep '>' r && test "$r" != end ; do echo -E "$r"; done)" ; GDBASMFILENAME=$RANDOM; \
#        echo -e "BITS 64\n$ASMOPCODE" >/tmp/$GDBASMFILENAME ; /usr/local/bin/nasm -f bin -o /dev/stdout /tmp/$GDBASMFILENAME | /usr/local/bin/ndisasm -i -b64 /dev/stdin ; \
#        /bin/rm -f /tmp/$GDBASMFILENAME
#    end
#end
#document assemble64
#Syntax: assemble64 <ADDR>
#| Assemble 64 bits instructions using nasm.
#| Type a line containing "end" to indicate the end.
#| If an address is specified, insert/modify instructions at that address.
#| If no address is specified, assembled instructions are printed to stdout.
#| Use the pseudo instruction "org ADDR" to set the base address.
#end
#
#define asm
#        if $argc == 1
#                assemble $arg0
#        else
#                assemble
#        end
#end
#document asm
#Syntax: asm <ADDR>
#| Shortcut to the asssemble command.
#end
##
##define asm32
##    if $argc == 1
##        assemble32 $arg0
##    else
##        assemble32
##    end
##end
##document asm32
##Syntax: asm32 <ADDR>
##| Shortcut to the assemble32 command.
##end
##
##define asm64
##    if $argc == 1
##        assemble64 $arg0
##    else
##        assemble64
##    end
##end
##document asm64
##Syntax: asm64 <ADDR>
##| Shortcut to the assemble64 command.
##end
##
##define dump_hexfile
##    dump ihex memory $arg0 $arg1 $arg2
##end
##document dump_hexfile
##Syntax: dump_hexfile FILENAME ADDR1 ADDR2
##| Write a range of memory to a file in Intel ihex (hexdump) format.
##| The range is specified by ADDR1 and ADDR2 addresses.
##end
##
##
##define dump_binfile
##    dump memory $arg0 $arg1 $arg2
##end
##document dump_binfile
##Syntax: dump_binfile FILENAME ADDR1 ADDR2
##| Write a range of memory to a binary file.
##| The range is specified by ADDR1 and ADDR2 addresses.
##end
##
##
##define dumpmacho
##    if $argc != 2
##        help dumpmacho
##    end
##    set $headermagic = *$arg0
##    # the || operator isn't working as it should, wtf!!!
##    if $headermagic != 0xfeedface
##        if $headermagic != 0xfeedfacf
##            printf "[Error] Target address doesn't contain a valid Mach-O binary!\n"
##            help dumpmacho
##        end
##    end
##    set $headerdumpsize = *($arg0+0x14)
##    if $headermagic == 0xfeedface
##        dump memory $arg1 $arg0 ($arg0+0x1c+$headerdumpsize)
##    end
##    if $headermagic == 0xfeedfacf
##        dump memory $arg1 $arg0 ($arg0+0x20+$headerdumpsize)
##    end
##end
##document dumpmacho
##Syntax: dumpmacho STARTADDRESS FILENAME
##| Dump the Mach-O header to a file.
##| You need to input the start address (use info shared command to find it).
##end
#
#define search
#    set $start = (char *) $arg0
#    set $end = (char *) $arg1
#    set $pattern = (short) $arg2
#    set $p = $start
#    while $p < $end
#        if (*(short *) $p) == $pattern
#            printf "pattern 0x%hx found at 0x%x\n", $pattern, $p
#        end
#        set $p++
#    end
#end
#document search
#Syntax: search <START> <END> <PATTERN>
#| Search for the given pattern beetween $start and $end address.
#end


# _________________user tips_________________
# The 'tips' command is used to provide tutorial-like info to the user
#define tips
#    printf "Tip Topic Commands:\n"
#    printf "\ttip_display : Automatically display values on each break\n"
#    printf "\ttip_patch   : Patching binaries\n"
#    printf "\ttip_strip   : Dealing with stripped binaries\n"
#    printf "\ttip_syntax  : AT&T vs Intel syntax\n"
#end
#document tips
#Syntax: tips
#| Provide a list of tips from users on various topics.
#end
#
#
#define tip_patch
#    printf "\n"
#    printf "                   PATCHING MEMORY\n"
#    printf "Any address can be patched using the 'set' command:\n"
#    printf "\t`set ADDR = VALUE` \te.g. `set *0x8049D6E = 0x90`\n"
#    printf "\n"
#    printf "                 PATCHING BINARY FILES\n"
#    printf "Use `set write` in order to patch the target executable\n"
#    printf "directly, instead of just patching memory\n"
#    printf "\t`set write on` \t`set write off`\n"
#    printf "Note that this means any patches to the code or data segments\n"
#    printf "will be written to the executable file\n"
#    printf "When either of these commands has been issued,\n"
#    printf "the file must be reloaded.\n"
#    printf "\n"
#end
#document tip_patch
#Syntax: tip_patch
#| Tips on patching memory and binary files.
#end
#
#
#define tip_strip
#    printf "\n"
#    printf "             STOPPING BINARIES AT ENTRY POINT\n"
#    printf "Stripped binaries have no symbols, and are therefore tough to\n"
#    printf "start automatically. To debug a stripped binary, use\n"
#    printf "\tinfo file\n"
#    printf "to get the entry point of the file\n"
#    printf "The first few lines of output will look like this:\n"
#    printf "\tSymbols from '/tmp/a.out'\n"
#    printf "\tLocal exec file:\n"
#    printf "\t        `/tmp/a.out', file type elf32-i386.\n"
#    printf "\t        Entry point: 0x80482e0\n"
#    printf "Use this entry point to set an entry point:\n"
#    printf "\t`tbreak *0x80482e0`\n"
#    printf "The breakpoint will delete itself after the program stops as\n"
#    printf "the entry point\n"
#    printf "\n"
#end
#document tip_strip
#Syntax: tip_strip
#| Tips on dealing with stripped binaries.
#end
#
#
#define tip_syntax
#    printf "\n"
#    printf "\t    INTEL SYNTAX                        AT&T SYNTAX\n"
#    printf "\tmnemonic dest, src, imm            mnemonic src, dest, imm\n" 
#    printf "\t[base+index*scale+disp]            disp(base, index, scale)\n"
#    printf "\tregister:      eax                 register:      %%eax\n"
#    printf "\timmediate:     0xFF                immediate:     $0xFF\n"
#    printf "\tdereference:   [addr]              dereference:   addr(,1)\n"
#    printf "\tabsolute addr: addr                absolute addr: *addr\n"
#    printf "\tbyte insn:     mov byte ptr        byte insn:     movb\n"
#    printf "\tword insn:     mov word ptr        word insn:     movw\n"
#    printf "\tdword insn:    mov dword ptr       dword insn:    movd\n"
#    printf "\tfar call:      call far            far call:      lcall\n"
#    printf "\tfar jump:      jmp far             far jump:      ljmp\n"
#    printf "\n"
#    printf "Note that order of operands in reversed, and that AT&T syntax\n"
#    printf "requires that all instructions referencing memory operands \n"
#    printf "use an operand size suffix (b, w, d, q)\n"
#    printf "\n"
#end
#document tip_syntax
#Syntax: tip_syntax
#| Summary of Intel and AT&T syntax differences.
#end
#
#
#define tip_display
#    printf "\n"
#    printf "Any expression can be set to automatically be displayed every time\n"
#    printf "the target stops. The commands for this are:\n"
#    printf "\t`display expr'     : automatically display expression 'expr'\n"
#    printf "\t`display'          : show all displayed expressions\n"
#    printf "\t`undisplay num'    : turn off autodisplay for expression # 'num'\n"
#    printf "Examples:\n"
#    printf "\t`display/x *(int *)$esp`      : print top of stack\n"
#    printf "\t`display/x *(int *)($ebp+8)`  : print first parameter\n"
#    printf "\t`display (char *)$esi`        : print source string\n"
#    printf "\t`display (char *)$edi`        : print destination string\n"
#    printf "\n"
#end
#document tip_display
#Syntax: tip_display
#| Tips on automatically displaying values when a program stops.
#end
#
#
