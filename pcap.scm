;;;============================================================================

;;; File: "pcap.scm", Time-stamp: <2008-05-15 14:07:39 feeley>

;;; Copyright (c) 2008 by Marc Feeley, All Rights Reserved.

;;; A simple interface to the pcap library.

;;;============================================================================

(##namespace ("pcap#"))

(##include "~~/lib/gambit#.scm")

(##include "pcap#.scm")

;;;============================================================================

(define ifbridge-program "./ifbridge")

(define (sudo program arguments)
  (open-process
   (list path: "sudo"
         arguments: (cons program arguments))))

(define (intf-list)
  (let* ((port (sudo ifbridge-program (list "list")))
         (result (read-all port read-line)))
    (close-port port)
    result))

(define (intf-open name)
  (let* ((read-port (sudo ifbridge-program (list "read" name)))
	 (write-port (sudo ifbridge-program (list "write" name))))
    (cons read-port write-port)))

(define (fetch-uint-be u8vect start len)
  (let loop ((i 0) (n 0))
    (if (< i len)
        (loop (+ i 1) (+ (u8vector-ref u8vect (+ start i)) (* 256 n)))
        n)))

(define (read-u32-be port)
  (let* ((u8vect (u8vector 0 0 0 0))
         (n (read-subu8vector u8vect 0 4 port)))
    (and (eqv? n 4)
         (fetch-uint-be u8vect 0 4))))

(define (intf-read intf)
  (let ((read-port (car intf)))
    (write-u8 0 read-port)
    (let ((len (read-u32-be read-port)))
      (and len
           (let* ((u8vect (make-u8vector len))
                  (n (read-subu8vector u8vect 0 len read-port)))
             (and (eqv? n len)
                  u8vect))))))

(define (store-uint-be u8vect start len n)
  (let loop ((i (- len 1)) (n n))
    (if (>= i 0)
        (begin
          (u8vector-set! u8vect (+ start i) (bitwise-and 255 n))
          (loop (- i 1) (arithmetic-shift n -8))))))

(define (write-u32-be n port)
  (let ((u8vect (u8vector 0 0 0 0)))
    (store-uint-be u8vect 0 4 n)
    (write-subu8vector u8vect 0 4 port)))

(define (intf-write-subu8vector intf u8vect start end)
  (let ((write-port (cdr intf)))
    (let ((len (- end start)))
      (write-u32-be len write-port)
      (write-subu8vector u8vect start end write-port)
      (force-output write-port))))

(define (intf-write intf u8vect)
  (intf-write-subu8vector intf u8vect 0 (u8vector-length u8vect)))

;;;============================================================================
