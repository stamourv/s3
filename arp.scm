;;;; Lysiane Bouchard - Vincent St-Amour
;;;; arp.scm

(define arp-oper-req  '#u8(#x00 #x01))
(define arp-oper-resp '#u8(#x00 #x02))
(define arp-eth-type  '#u8(#x00 #x01))

;; called when an ARP request is received
(define (arp-pkt-in)
  (if (and (u8vector-equal-field? pkt arp-htype arp-eth-type 0 2)  ; Ethernet type
 	   (u8vector-equal-field? pkt arp-ptype eth-type-IPv4 0 2) ; IP protocol type
 	   (= (u8vector-ref pkt arp-halen) 6)                      ; Ethernet adr length
 	   (= (u8vector-ref pkt arp-palen) 4)                      ; IP adr length
 	   ;; TODO we really need all these checks ? be liberal in what you accept ?
 	   (u8vector-equal-field? pkt arp-oper arp-oper-req 0 2)   ; ARP request
; 	   (or (u8vector-equal-field? pkt arp-tip my-IP 0 4)       ; check if we are the target
;	   (u8vector-equal-field? pkt arp-tip broadcast-IP 0 4)) ;; TODO bug, even with a broadcast, this doesn't pass
	   ) ;; TODO should we tolerate broadcast ? goes a bit against the spirit of ARP
      (begin
	(debug "arp\n")
	(u8vector-copy! arp-oper-resp 0 pkt arp-oper 2) ; ARP response
	(u8vector-copy! pkt arp-shadr pkt arp-thadr 6)
	(u8vector-copy! pkt arp-sip pkt arp-tip 4) ;; TODO maybe a function to swap source IP and MAC with the target, etc, and put our own info when we answer ?
 	(u8vector-copy! my-MAC 0 pkt arp-shadr 6)
	(u8vector-copy! my-IP 0 pkt arp-sip 4)
	(ethernet-encapsulation arp-length))
      #f))
