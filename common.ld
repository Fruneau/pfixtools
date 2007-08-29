SECTIONS {
    .data : {
        __madinit_start = . ;
        *( .mad.init )
        __madinit_end = . ;

        __madexit_start = . ;
        *( .mad.exit )
        __madexit_end = . ;
    }
}
