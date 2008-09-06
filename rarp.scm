;;;; Vincent St-Amour
;;;; rarp.scm

(define rarp-oper-req  '#u8(#x00 #x03))
(define rarp-oper-resp '#u8(#x00 #x04))
(define rarp-eth-type  '#u8(#x00 #x01))

;; called when a RARP request is received
(define (rarp-pkt-in)
  ;; most constants are the same as ARP, due to the similarity of the 2
  ;; protocols
  (if (and (u8vector-equal-field? pkt arp-htype rarp-eth-type 0 2) ; Ethernet type
	   (u8vector-equal-field? pkt arp-ptype eth-type-IPv4 0 2) ; IP protocol type
	   (= (u8vector-ref pkt arp-halen) 6)                      ; Ethernet adr length
	   (= (u8vector-ref pkt arp-palen) 4)                      ; IP adr length
	   (u8vector-equal-field? pkt arp-oper rarp-oper-req 0 2)) ; RARP request
      ;; TODO part of this validation is common with arp, abstract ?
      ;; no need to check if we are the target or not, RARP requests are
      ;; broadcast
      (begin
	(u8vector-copy! rarp-oper-resp 0 pkt arp-oper 2) ; RARP response
	;; TODO abstract the following with ARP ?
	(u8vector-copy! pkt arp-thadr pkt arp-shadr 6) ;; TODO make sure this is ok
	(u8vector-copy! (rarp-get-ip) 0 pkt arp-tip 4)
	(u8vector-copy! my-MAC 0 pkt arp-shadr 6)
	(u8vector-copy! my-IP 0 pkt arp-sip 4) ;; TODO abstract similarities between arp and rarp
	(ethernet-encapsulation arp-length))
      #f))

(define (rarp-get-ip) (cdr (assoc (u8vector-ref-field pkt arp-shadr 6) rarp-mac-ip-alist)))
