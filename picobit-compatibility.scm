
;;;; Vincent St-Amour
;;;; picobit-compatibility.scm

(include "./files-to-load.scm")

;; TODO just so the code does something
; (whole-pkt-set! '#u8(255 255 255 255 255 255 136 153 170 187 204 221 221 8 6 0 1 8 0 6 4 0 1 136 153 170 187 204 221 192 168 1 104 0 0 0 0 0 0 255 255 255 255))
;; TODO was (whole-pkt-set! (u8vector (255 255 255 255 255 255 136 153 170 187 204 221))), had weird nesting
;; partial arp request, otherwise, we need too many arguments
;; (whole-pkt-set! (u8vector (255 255 255 255 255 255 136 153 170 187 204 221 8 6 0 1 8 0 6 4 0 1 136 153 170 187 204 221 192 168 1 104 0 0 0 0 0 0 255 255 255 255))) ; arp request

(network-init)
(receive-packet-to-u8vector pkt)

;; (define (print-vector v i)
;;   (if (< i (u8vector-length v))
;;       (begin (display (u8vector-ref v i))
;; 	     (display "-")
;; 	     (print-vector v (+ i 1)))))
; (print-vector pkt 0)

(process-packet)

;; (print-vector pkt 0)

(network-cleanup)

;; (define else #t) ; for cond
;; (define-macro (cond clause . rest)
;;   `(if ,(car clause)
;;        (begin ,@(cdr clause))
;;        ,(if (null? rest)
;; 	   #f
;; 	   `(cond ,@rest))))
