;;;; Vincent St-Amour
;;;; gambit-compatibility.scm

(include "files-to-load.scm")

;; from srfi 66, present in picobit
;; TODO found this in tests, considered useful, changed the name to avoid clashes (which did happen when I tried the original tests, was a quite elusive bug)
;; copies from a u8vector "u8-src" to another u8vector "u8-dest"
;; TODO changed the name to match srfi 66
(define (u8vector-copy! u8-src idx-src u8-dest idx-dest len-src)
  (copy-subf->subf u8-dest ; TODO swap source and dest for copy-subf too ?
                   idx-dest
                   u8-src
                   idx-src
                   (+ idx-src len-src))) ; TODO was len-src, but since this is used as an end bound, wouldn't work unless we started from 0
;; TODO is src last and dst first ? really ? change argument order, and modify code that uses it accordingly

;; copies n successive bytes from "src" to "dst"
(define (copy-subf->subf dst i-dst src i-src end-src)
  (if (< i-src end-src)
      (begin (u8vector-set! dst i-dst (u8vector-ref src i-src))
             (copy-subf->subf dst (+ 1 i-dst) src (+ 1 i-src) end-src))))


;; TODO just so the code does something
(whole-pkt-set! '#u8(255 255 255 255 255 255 136 153 170 187 204 221))
;; TODO was (whole-pkt-set! (u8vector (255 255 255 255 255 255 136 153 170 187 204 221))), had weird nesting
;; partial arp request, otherwise, we need too many arguments
;; (whole-pkt-set! (u8vector (255 255 255 255 255 255 136 153 170 187 204 221 8 6 0 1 8 0 6 4 0 1 136 153 170 187 204 221 192 168 1 104 0 0 0 0 0 0 255 255 255 255))) ; arp request
(process-packet)

;; (define else #t) ; for cond
;; (define-macro (cond clause . rest)
;;   `(if ,(car clause)
;;        (begin ,@(cdr clause))
;;        ,(if (null? rest)
;; 	   #f
;; 	   `(cond ,@rest))))
