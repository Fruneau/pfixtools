SECTIONS {
    .rodata : {
        . = ALIGN(8);
        __madinit = . ;
        *( MAD_INIT )
        QUAD(0)
        *( MAD_EXIT )
        __madexit = . ;
    }
}
