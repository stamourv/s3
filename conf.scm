;;;; Vincent St-Amour
;;;; conf.scm

;; TODO find ip and mac by asking the kernel ?
(define my-mac '#u8(#x00 #x20 #xfc #x20 #x0d #x64))
;; (define my-ip '#u8(172 16 96 215)) ;; TODO this is the real one that was assigned to the little machine
(define my-ip '#u8(10 223 151 99)) ;; TODO this is the one for the original tests, won't work with the new ones
(define broadcast-ip '#u8(255 255 255 255)) ;; TODO put in pkt ?
(define my-address-mask '#u8(255 255 0 0)) ; TODO put this in conf file ?

;; the size of the vector storing the packet currently in the system
;; the maximum size of an IP datagram we are forced to accept by the standard
;; is 576 bytes, plus 14 bytes for the ethernet header
(define pkt-allocated-length 590)

;; list of IPs associated to MAC adresses
(define rarp-mac-ip-alist ; TODO name ?
  (list (cons '#u8(23 34 45 56 67 78) '#u8(192 168 1 108))))


(define ip-original-time-to-live 225) ; TODO put in conf file ? or pkt ?

;; TCP configuration

;; maximum life time of a tcp connection without any activation
;; TODO explain better ? which unit ?
(define tcp-max-life-time 30)
;; delay before retransmission
(define tcp-retransmission-delay 5)
;; maximum number of retransmissions for a tcp packet
(define tcp-attempts-limit 3)
;; time delay in the "time-wait" state
(define tcp-time-to-wait 15)
;; size of the tcp input and output buffers for one connection.
(define tcp-input-size  64)
(define tcp-output-size 64)
