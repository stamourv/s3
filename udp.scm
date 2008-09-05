;;;; Lysiane Bouchard - Vincent St-Amour
;;;; udp.scm

;; TODO maybe rethink the interface with the outside, and reuse some of the functions of the old udp for i/o, they can be found in ../orig


;; called when an UDP datagram is received
(define (udp-pkt-in)
  (if (valid-udp-checksum?)
      (let ((port (search-port
		   (pkt-ref-2 udp-dst-portnum)
		   udp-ports)))
	(if (and port (pass-app-filter? udp-src-portnum port))
	    ((conf-ref port conf-reception)
	     (u8vector-ref-field pkt ip-src-IP 4)
	     (u8vector->portnum (u8vector-ref-field pkt udp-src-portnum 2))
	     (u8vector-ref-field pkt udp-data (- (pkt-ref-2 udp-length) 8)))
	    (icmp-send-port-unreachable-error))))) ; no app listens to this port

(define (valid-udp-checksum?)
  (or (= (pkt-ref-2 udp-checksum) 0)
      (valid-checksum? (compute-udp-checksum))))
(define (compute-udp-checksum)
  (let ((start udp-header))
    ;; we start at the beginning of the udp header
    (pkt-checksum start
		  (+ start (pkt-ref-2 udp-length))
		  (udp-pseudo-checksum))))
(define (udp-pseudo-checksum) ;; TODO can this use the already defined pseudo-checksum ? what does it calculate ? seems like we add some parts of the ip and some parts of the udp header
  (add-16bits-1comp (pkt-ref-2 udp-length)
                    (add-16bits-1comp (u8vector-ref pkt ip-protocol)
                                      (pkt-checksum ip-src-IP
                                                    (+ 8 ip-src-IP)
                                                    0))))


;; UDP outgoing packet treatment
;; send an UDP datagram, takes an IP adress (u8vector of length 4), a port
;; number (u8vector of length 2) and data (u8vector)
;; TODO is it clean to take the src-port as parameter ?
;; TODO was not tested at all
;; TODO won't work, we don't know the hardware address if this was not sent in response to something else, would have to send an ARP request, or keep a cache of who sent data, linking ip addresses with mac (if we do only that, we can't initiate anything) DANGER
(define (udp-encapsulation dst-IP src-portnum dst-portnum data)
  (let* ((data-len (if data (u8vector-length data) 0)) ;; TODO would there be a case where we don't send any data ?
	 (len (+ 8 data-len)))
    ;; TODO have a function to pass from portnum number to vector ? and visa-versa
    (if data (copy-u8->pkt-n udp-data data data-len))
    (copy-u8->pkt-2 udp-dst-portnum (portnum->u8vector dst-portnum))
    (copy-u8->pkt-2 udp-src-portnum (portnum->u8vector src-portnum))
    (integer->pkt-2 0 udp-checksum)
    (integer->pkt-2 len udp-length)
    (ip-encapsulation dst-IP
		      udp-checksum
                      compute-udp-checksum
                      len)))
