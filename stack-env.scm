;;;; Lysiane Bouchard - Vincent St-Amour
;;;; stack-env.scm


;; the packet currently in the system, used both for receiveing and sending
;; there's always only one
(define pkt (make-u8vector pkt-allocated-length 0))
;; TODO reject if it's bigger, maybe do it where we set the whole pkt


;; current connection and port
(define curr-conn #f)
(define curr-port #f)

(define tcp-ports '())
(define udp-ports '())

(define (get-ip-identification)
  (let ((res ip-identification-count))
    (set! ip-identification-count (modulo (+ 1 res) 256))
    res))
(define ip-identification-count 0)
;; TODO should be more than just a cyclic counter, should increment every 8ms or so, see the book (or maybe is it for tcp ?)

(define (tcp-isn)
  (u8vector-increment! tcp-isn-count 0 4 1)
  tcp-isn-count)
(define tcp-isn-count (u8vector 255 255 255 255))

;;---------- input and output control flow ------------------------------------

;; acheminates the incoming packet
;; acheminates the answer to the device driver if necessary
;; TODO we have a problem if we start the stack before we get any packets, since we process empty packets
(define (process-packet)
  (debug "process-packet\n")
  (set! data-lenght 0)
  (eth-pkt-in) ; the response is sent somewhere within
  (set! curr-port #f)
  (set! curr-conn #f))


;;SEND PACKET
;(define test-pkt (make-u8vector 0 0))
(define (send-frame len) ; TODO instead of taking a parameter, maybe have use the pkt-len variable ? then we can call it from process-packet
  ;; (set! test-pkt (make-u8vector len 0))
  ;;          (calculate-eth-crc (+ 4 len)) ; TODO watch out for off by one
  ;; TODO seems the driver does it for us, clean up this function
  ;; (set! test-pkt (u8vector-ref-field pkt 0 (+ 4 len))) ; +4 is for the CRC
  ; (set! test-pkt (u8vector-ref-field pkt 0 len))
  (debug "send\n")
  (send-packet-from-u8vector pkt len)
  )
