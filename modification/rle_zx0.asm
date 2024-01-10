;================ RLE PACKER ===================
;marker-byte = AH
;length = ECX, source = ESI, receiver = EDI
;-----------------------------------------------
_rle_pack:  
      push  rdi
      mov   [edi], ecx
      add   edi, 4
      xor   eax, eax
pack_find:
      cmp   ah, 0x7F
      jz    sav1_p
      lodsb
      cmp   al, byte[esi]
      jz    equ
      inc   ah
      loop  pack_find
      jmp pack_end

  sav1_p:
      shr   ax, 8
      stosb
      push  rcx
      push  rsi
      mov   ecx, eax
      sub   esi, ecx
      rep   movsb 
      pop   rsi
      pop   rcx
      loop  pack_find
      jmp   pack_end 

equ:
      dec   esi
      cmp   ah, 0
      jz    p_equ
      shr   ax, 8
      stosb
      push  rcx
      push  rsi
      mov   ecx, eax
      sub   esi, ecx
      rep   movsb
      pop   rsi
      pop   rcx
   p_equ:
      or    ah, 0x80
   p_dup:
      inc   ah
      cmp   ah, 0xFF
      jnz   p_ok
      rol   ax, 8
      stosw 
      mov   ah, 0x81
   p_ok:
      lodsb
      cmp   al, byte[esi]
      jnz   sav2_p
      loop  p_dup
   sav2_p:
      rol   ax, 8
      stosw
      xor   ax, ax
      ;inc   ecx
      loop  pack_find 

pack_end:
      cmp   ah, 0
      jz    pack_exit
      shr   ax, 8
      stosb
      mov   ecx, eax
      sub   esi, ecx
      rep   movsb
pack_exit:                  
      pop   rax
      xchg  rax, rdi
      sub   rax, rdi
      ret            ; in rax - size of packed data
;==========================================================

;========= RLE UNPACKER =======================================
;size of packed data = ECX, source = ESI, receiver = EDI 
;--------------------------------------------------------------
_rle_unpack:
      ;mov   ecx, [esi]
      add   esi, 4
      sub   ecx, 4
      xor   eax, eax
   up_find:
      lodsb
      test  al, 0x80
      jnz   up_dup
      
      push  rcx
      push  rax
      mov   ecx, eax
      rep   movsb
      pop   rax
      pop   rcx
      sub   ecx, eax
      jmp   up_nxt

   up_dup:
      sub   al, 0x80
      push  rcx
      mov   ecx, eax
      lodsb
      rep   stosb
      pop   rcx
      dec   ecx
   up_nxt:
      loop  up_find
up_end:
      ret
;===============================================================

;================== CODE/DECODE ================================
;source = RSI, receiver = RDI, key = RDX, size of data = RCX
;---------------------------------------------------------------
_xor_code:
c_strt:
      lodsq
      xor   rax, rdx
      stosq
      sub   rcx, 8
      cmp   rcx, 0
      je    c_end
      cmp   rcx, 8
      jl    c_cut
      jmp   c_strt
c_cut:
     lodsb
      xor   al, dl
      stosb
      shr   rdx, 8
      loop  c_cut 
c_end:
      ret

;===============================================================
;================== ZX0 UNPACKER ===========================================
;INPUT:  rsi: start of compressed data; rdi: start of decompression buffer;
;OUTPUT: none
;---------------------------------------------------------------------------
_zx0_depack:
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
          ;mov   rsi,  rdi
          add   rsi,  rdx
          rep   movsb
          pop   rsi
          add   al,   al
          jnc   literals
       .zx0_offs:
          mov   cl,   0xfe
          call  .bits_loop
          inc   cl
          ;je    ext_zx0_bits
          je   zx0_done
          
          mov   dh,   cl
          push  1
          pop   rcx
          ;mov  cx,   1
          mov   dl,   byte[rsi]
          inc   rsi
          stc
          rcr   dx,   1
          jc    .got_offs
          call  .gam_elias_bit
       .got_offs:
          ;inc   cx
          inc   ecx
          jmp   .zx0_match
       .zx0_bits:
          push  1
          pop   rcx   
          ; mov   cx,   1
       .bits_loop:
          add   al,   al
          jnz   .check_bits
          lodsb
          adc   al,   al
       .check_bits:
          jc    ext_zx0_bits
       .gam_elias_bit:
          add   al,   al
          ;adc   cx,   cx
          adc   ecx,  ecx
          jmp   .bits_loop
       ext_zx0_bits:
      ;ret
      zx0_done:
   ret
