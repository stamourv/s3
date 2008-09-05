;;;; Lysiane Bouchard - Vincent St-Amour
;;;; arp.scm

(define arp-oper-req  '#u8(#x00 #x01))
(define arp-oper-resp '#u8(#x00 #x02))
(define arp-eth-type  '#u8(#x00 #x01))

;; called when an ARP request is received
(define (arp-pkt-in)
  (if (and (=pkt-u8-2? arp-htype arp-eth-type)  ; Ethernet type
 	   (=pkt-u8-2? arp-ptype eth-type-IPv4) ; IP protocol type
 	   (=pkt-byte? arp-halen 6)             ; Ethernet adr length
 	   (=pkt-byte? arp-palen 4)             ; IP adr length
 	   ;; TODO we really need all these checks ? be liberal in what you accept ?
 	   (=pkt-u8-2? arp-oper arp-oper-req)   ; ARP request
; 	   (or (=pkt-u8-4? arp-tip my-IP)       ; check if we are the target
;	   (=pkt-u8-4? arp-tip broadcast-IP)) ;; TODO bug, even with a broadcast, this doesn't pass
	   ) ;; TODO should we tolerate broadcast ? goes a bit against the spirit of ARP
      (begin
	(debug "arp\n")
	(copy-u8->pkt-2 arp-oper arp-oper-resp) ; ARP response
	(u8vector-copy! pkt arp-shadr pkt arp-thadr 6)
	(u8vector-copy! pkt arp-sip pkt arp-tip 4) ;; TODO maybe a function to swap source IP and MAC with the target, etc, and put our own info when we answer ?
 	(copy-u8->pkt-6 arp-shadr my-MAC)
	(copy-u8->pkt-4 arp-sip my-IP)
	(ethernet-encapsulation arp-length))))
