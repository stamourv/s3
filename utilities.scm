;;;; Lysiane Bouchard - Vincent St-Amour
;;;; utilities.scm

;;;  general purpose procedures

;; generic search function, that returns the first element of a list that
;; obeys a predicate
(define (memp pred l) ;; TODO name ? was search
  (cond ((null? l) #f)
        ((pred (car l)) (car l))
        (else (memp pred (cdr l)))))


;; DATA MANIPULATION

; TODO implement directly in picobit, meanwhile, make sure it's ok
(define (u8vector-equal-field? v1 s1 v2 s2 n)
  (cond ((= n 0) #t)
	((= (u8vector-ref v1 s1) (u8vector-ref v2 s2))
	 (u8vector-equal-field? v1 (+ s1 1) v2 (+ s2 1) (- n 1)))
	(else #f)))

;; take a copy of a subfield
;; TODO standardize name wit srfi 66
(define (u8vector-ref-field u8 i n)
  (let ((res (make-u8vector n 0)))
    (u8vector-copy! u8 i res 0 n)
    res))

;; increment the value represented by a subset of a byte vector by offset
(define (u8vector-increment! u8 i n offset) ;; TODO is the arguemnt order the most intuitive ? it's like ref field, with the value at the end, like a set! would be, by the way, do we a have set! for subfields, or is it done in some ad-hoc way ?
  (u8vector-increment!-loop u8 i (- (+ i n) 1) offset))
(define (u8vector-increment!-loop u8 start i offset)
  (if (>= i start)
      (begin
        (u8vector-set! u8 i (modulo (+ (u8vector-ref u8 i) offset) 256))
        (u8vector-increment!-loop u8 start (- i 1) (quotient offset 256)))))


;; TODO compatible with picobit ? maybe in the lib
(define (get-current-time) (time->seconds (current-time)))
(define (get-elapsed-time init-time) (- (get-current-time) init-time))


;;; Checksums

;; PROBLEM ????? VERYFY WITH TCP OPTIONS ...
;; INCLUDE IT IN THE PSEUDO ????
;; To compute a checksum
(define (pkt-checksum start end pseudo)
  (if (= 1 (modulo (- end start) 2))  ; odd number of bytes?
      (pkt-checksum-loop
       start (- end 1) ;; TODO had set!s not on globals
       (add-16bits-1comp pseudo (* 256 (u8vector-ref pkt (- end 1))))))
  (pkt-checksum-loop start end pseudo))
;; TODO ok, seems the pseudo is used to calculate the checksum of a larger zone than planned, icmp doesn't use it, ip sends the checksum of its options
(define (pkt-checksum-loop start end sum)
  (if (< start end)
      (pkt-checksum-loop (+ start 2)
                         end
                         (add-16bits-1comp sum (pkt-ref-2 start)))
      sum))
;; TODO we might be able to get rid of the pseudo
;; TODO make sure the checksum algorithm is still correct

;; 1 complement addition of 16 bits words
(define (add-16bits-1comp x y)
  (let ((n (+ x y)))
    (if (> n 65535)
        (+ (modulo n 65536) 1)
        n)))

;; Compute the checksum of the given 16-bit words
;; must be called with "val" = 0 TODO why not use an internal loop function ?
(define (pseudo-checksum 16bits-words val) ;; TODO use a simple reduce ?
  (if (null? 16bits-words)
      val
      (pseudo-checksum (cdr 16bits-words)
                       (add-16bits-1comp (car 16bits-words) val))))
;; TODO used with tcp and udp

(define (valid-checksum? checksum)
  (= 65535 checksum)) ;; TODO really ? why not use 0 ? would be faster

(define (reverse-checksum checksum)
  (bitwise-xor 65535 checksum))

;; TODO find a way to be able to define the mode (debug or not) in conf.scm
(define-macro (debug s)
  (if #f `(display ,s) #f))
