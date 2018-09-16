
    .global _rsqrt3
    .global _rsqrt5
    .global _rsqrt7
    .global _rsqrt9

    .text
_rsqrt3:
    movd %edi, %xmm0
    sqrtss %xmm0, %xmm0

    mov $0x3f800000, %eax
    movd %eax, %xmm1

    divss %xmm0, %xmm1

    movd %xmm1, %eax
    ret

_rsqrt5:
    movd %edi, %xmm0

    psrld $23, %xmm0
    pslld $1, %xmm0
    cvtdq2ps %xmm0, %xmm0

    mov $0x0008000, %eax
    movd %eax, %xmm1
    por %xmm1, %xmm0

    sqrtss %xmm0, %xmm0

    mov $0x3f800000, %eax
    movd %eax, %xmm1

    divss %xmm0, %xmm1

    mov $0x00004000, %eax
    movd %eax, %xmm0
    paddd %xmm1, %xmm0

    psrld $15, %xmm0
    pslld $24, %xmm0

    movd %xmm0, %eax
    ret

_rsqrt7:
    mov $0x3f80001, %eax
    shl $32, %rax
    mov %edi, %edi
    or %rax, %rdi
    movq %rdi, %xmm0

    mov $0x00080000008000, %rax
    movq %rax, %xmm1
    por %xmm1, %xmm0

    rsqrtps %xmm0, %xmm1
    mov $0x3f000000, %eax
    movd %eax, %xmm3
    mulss %xmm3, %xmm0
    movaps %xmm1, %xmm2
    mulss   %xmm1, %xmm2
    mulss   %xmm0, %xmm2
    mov $0x3fc00000, %eax
    movd %eax, %xmm0
    subss   %xmm2, %xmm0
    mulss   %xmm1, %xmm0

    mov $0x00004000, %eax
    movd %eax, %xmm1
    paddd %xmm1, %xmm0

    movd %xmm0, %eax
    ret

_rsqrt9:
    movd %edi, %xmm0

    movaps %xmm0, %xmm2
    pslld $8, %xmm2
    movaps %xmm2, %xmm3
    psrad $31, %xmm3

    mov $0x60000000, %eax
    movd %eax, %xmm1
    paddd %xmm1, %xmm2

    mov $0x3c000000, %eax
    movd %eax, %xmm1
    pcmpgtd %xmm1, %xmm2

    mov $0xffff8000, %eax
    movd %eax, %xmm1
    pand %xmm1, %xmm0

    mov $0x00008000, %eax
    movd %eax, %xmm1
    por %xmm1, %xmm0

    rsqrtss %xmm0, %xmm0

    mov $0x000047ff, %eax
    movd %eax, %xmm1
    pxor %xmm3, %xmm2
    psubd %xmm2, %xmm1
    paddd %xmm1, %xmm0

    movd %xmm0, %eax
    ret
