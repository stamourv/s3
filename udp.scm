;;;; Lysiane Bouchard - Vincent St-Amour
;;;; udp.scm

;; TODO maybe rethink the interface with the outside, and reuse some of the functions of the old udp for i/o, they can be found in ../orig

;; called when an UDP datagram is received
(define (udp-pkt-in)
  (if (or (= (pkt-ref-2 udp-checksum) 0) ; valid or no checksum ?
	  (= 65535(compute-udp-checksum)))
      (let ((port (search-port (pkt-ref-2 udp-destination-portnum) udp-ports)))
	(if (and port (pass-app-filter? udp-source-portnum port))
	    ((conf-ref port conf-reception)
	     (u8vector-ref-field pkt ip-source-ip 4) ; length 4 u8vector
	     (u8vector->portnum (u8vector-ref-field pkt udp-source-portnum 2)) ; integer
	     (u8vector-ref-field pkt udp-data (- (pkt-ref-2 udp-length) 8))) ; u8vector
	    (icmp-unreachable icmp-port-unreachable))))) ; no app listens to this port

(define (compute-udp-checksum)
  (let ((udp-len (pkt-ref-2 udp-length)))
    (pkt-checksum
     ip-source-ip
     ;; the UDP pseudo-header uses values located before the UDP header
     (+ udp-header udp-len)
     (add-16bits-1comp 17 ; UDP protocol ID, with leading zeroes up to 16 bits
		       udp-len))))


;; UDP outgoing packet treatment
;; send an UDP datagram, takes an IP adress (u8vector of length 4), the source
;; port number (integer), destination port number (integer) and data (u8vector)
;; if no data should be sent, an empty vector should be give TODO when would we want no data ?
;; TODO is it clean to take the src-port as parameter ?
;; TODO was not tested at all
;; TODO won't work, we don't know the hardware address if this was not sent in response to something else, would have to send an ARP request, or keep a cache of who sent data, linking ip addresses with mac (if we do only that, we can't initiate anything) DANGER
(define (udp-write dst-ip src-portnum dst-portnum data)
  (let* ((data-length (u8vector-length data))
	 (len (+ 8 data-length)))
    (u8vector-copy! data 0 pkt udp-data data-length)
    (u8vector-copy! (portnum->u8vector dst-portnum) 0
		    pkt udp-destination-portnum 2)
    (u8vector-copy! (portnum->u8vector src-portnum) 0
		    pkt udp-source-portnum 2)
    (integer->pkt 0 udp-checksum 2)
    (integer->pkt len udp-length 2)
    (ip-encapsulation dst-ip udp-checksum compute-udp-checksum len)))
