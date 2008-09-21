(##include "pcap#.scm")

(include "files-to-load.scm")

(define interfaces (intf-list))
(define intf1 (car interfaces))
(define intf (intf-open intf1))

(let loop ()
  (let ((packet (intf-read intf)))
    (whole-pkt-set! packet)
    (process-packet)
    (intf-write intf test-pkt)
    (loop)))
