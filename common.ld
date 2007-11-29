SECTIONS {
    .rodata : {
        . = ALIGN(8);
        __madinit = . ;
        *( .mad.init )
        QUAD(0)
        *( .mad.exit )
        __madexit = . ;
    }
}
