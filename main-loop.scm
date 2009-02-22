;; the stack's main loop, reads packets and outputs them

(include "~/stack-tcp-ip/stack-files/files-to-load")

(define input-file (open-input-file (list path: "~/tmp/test-feed")))

(with-output-to-file (list path: "~/tmp/test-feed")
  (lambda () ; print a simple ARP request
    (begin (print "(")
	   (map (lambda (x) (print x " "))
		'(#xFF #xFF #xFF #xFF #xFF #xFF 136 153 170 187 204 221
		       8 6 0 1 8 0 6 4 0 1 0 0 12 5 #x3E #x80
		       192 168 1 104 0 0 0 0 0 0 255 255 255 255))
	   (print ")"))))

(define (main-loop) ; TODO lire en xx:xx:xx ? format pour frame ethernet ?
  (let ((input (read input-file)))
    (if (equal? #!eof input)
	(main-loop) ; TODO yuck, attente active
	(begin (whole-pkt-set! (list->u8vector input))
	       ;; we pass the packet as a list of numbers
	       (process-packet) ; TODO maybe process-packet should fetch it himself ?
	       (print pkt)))))

(main-loop)
