;;;; Vincent St-Amour
;;;; rarp.scm

(define rarp-oper-req  '#u8(#x00 #x03))
(define rarp-oper-resp '#u8(#x00 #x04))
(define rarp-eth-type  '#u8(#x00 #x01))

;; called when a RARP request is received
(define (rarp-pkt-in)
  ;; most constants are the same as ARP, due to the similarity of the 2
  ;; protocols
  (if (and (=pkt-u8-2? arp-htype rarp-eth-type) ; Ethernet type
	   (=pkt-u8-2? arp-ptype eth-type-IPv4) ; IP protocol type
	   (=pkt-byte? arp-halen 6)             ; Ethernet adr length
	   (=pkt-byte? arp-palen 4)             ; IP adr length
	   (=pkt-u8-2? arp-oper rarp-oper-req)) ; RARP request
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
	(ethernet-encapsulation arp-length)))) ; TODO error case

(define (rarp-get-ip) (cdr (assoc (u8vector-ref-field pkt arp-shadr 6) rarp-mac-ip-alist)))
