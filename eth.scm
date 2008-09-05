;;;; Lysiane Bouchard - Vincent St-Amour
;;;; eth.scm

;; Ethernet constants
(define broadcast-MAC '#u8(#xff #xff #xff #xff #xff #xff))
(define eth-type-IPv4 '#u8(#x08 #x00))
(define eth-type-ARP  '#u8(#x08 #x06))
(define eth-type-RARP '#u8(#x80 #x35))
(define eth-type-IPv6 '#u8(#x86 #xdd)) ;; TODO useless


;; the procedure called when a new ethernet frame is received.
(define (eth-pkt-in)
  (if (valid-MAC-addr?)
      (let ((higher-protocol (u8vector-ref-field pkt eth-type 2)))
	(cond ((equal? higher-protocol eth-type-IPv4) (ip-pkt-in))
	      ((equal? higher-protocol eth-type-ARP)  (arp-pkt-in))
	      ((equal? higher-protocol eth-type-RARP) (rarp-pkt-in))
	      ;; TODO use some kind of switch case ? picbit has case, change this, if it compiles well, PROBLEM, case uses eq?, we'd have to make an equal version (according to R5RS, case should use eqv?, build another with equal?)
	      (else #f))))) ;; TODO remove ?

(define (valid-MAC-addr?) ; TODO is valid the word ? our, or appropriate ?
  (or (=pkt-u8-6? eth-dst-MAC broadcast-MAC) ;; TODO maybe inline it ?
      (=pkt-u8-6? eth-dst-MAC my-MAC)))

;; output
;; TODO maybe have a more general version that takes he destination as parameter ?
(define (ethernet-encapsulation len) ; TODO useful only with a connection
  (move-in-pkt-n eth-src-MAC eth-dst-MAC 6)
  ;; (copy-curr-conn-info->pkt eth-dst-MAC conn-peer-MAC 6) ; TODO kept since some of the test cases seems to behave strangely if we simply reply to the sender
  (copy-u8->pkt-6 eth-src-MAC my-MAC)
  ;; we don't need to set the ethernet frame type, since it's the same as on
  ;; the original packet
  (send-frame (+ 14 len)))
;; TODO pad if necessary up to 46 bytes (does this include the header ?) ? maybe hardware does it
