;;;; Lysiane Bouchard - Vincent St-Amour
;;;; ip.scm


;; IP constants
(define ip-protocol-ICMP 1)
(define ip-protocol-TCP  6)
(define ip-protocol-UDP  17)
(define ip-dont-fragment 2)


;; (define ip-identification (cyclic-byte)) ;; TODO picobit does not have set! on elements of a closure, only on globals
(define (ip-identification)
  (let ((res ip-identification-count))
    (set! ip-identification-count (modulo (+ 1 res) 256))
    res))
(define ip-identification-count 0)
;; TODO put in the ip file ? used both by IP and ICMP. TODO since icmp-encapsulation is going to end up calling ip-encapsulation, will eventually only be needed by ip
;; TODO should be more than just a cyclic counter, should increment every 8ms or so, see the book (or maybe is it for tcp ?)


;; called when an IP datagram is received
(define (ip-pkt-in)
  ;; TODO do a macro to abstract reception ?
  ;; TODO all these nots are quite ugly, also, do we inline the body of these checks ?
  (cond ((not (valid-ip-addr?)) #f)
	((not (valid-ip-checksum?)) #f)
	((not (alive?)) (icmp-send-time-exceed-error)) ;; TODO inline alive?
	((not (not-fragmented?)) (icmp-send-ip-header-bad-error)) ;; TODO all these nots are ridiculous
	(else (let ((higher-protocol (u8vector-ref pkt ip-protocol))) ;; TODO use numerical equality ?, and put the let around the bigger cond ?
		(cond ((= higher-protocol ip-protocol-ICMP) (icmp-pkt-in))
		      ((= higher-protocol ip-protocol-TCP) (tcp-pkt-in))
		      ((= higher-protocol ip-protocol-UDP) (udp-pkt-in))
		      (else (icmp-send-protocol-unreachable-error)))))))

(define (get-ip-hdr-len) (* 4 (modulo (u8vector-ref pkt ip-hdr-len) 16)))
(define (get-ip-version) (quotient (u8vector-ref pkt ip-version) 16))
(define (set-ip-frag)
  (u8vector-set! pkt ip-frag (* ip-dont-fragment 32))
  (u8vector-set! pkt (+ ip-frag 1) 0))
;; TODO where to put these ?

;; VALIDATION STEPS
(define (valid-ip-addr?) ; TODO is valid the good word ? appropriate instead ?
  (or (=pkt-u8-4? ip-dst-IP my-IP) ;; TODO enable more ?
      (=pkt-u8-4? ip-dst-IP broadcast-IP)))

(define (valid-ip-checksum?) (valid-checksum? (compute-ip-checksum)))
(define (compute-ip-checksum) (pkt-checksum ip-header ip-options 0)) ;; TODO why not just calculate the checksum of the whole header + options at the same time ?
;; TODO now that we don't have options, maybe this pseudo stuff is obsolete, make sure checksum is still valid

(define (alive?) (> (u8vector-ref pkt ip-ttl) 0))

(define (not-fragmented?)
  (let ((ip-frag-flags (quotient (u8vector-ref pkt ip-frag) 32)))
    (or (= ip-frag-flags 0)
        (= ip-frag-flags ip-dont-fragment))))


;; TODO shouldn't we get the data then return here to encapsulate ? might get rid of some code duplication, and be easier to understand, but we wouldn't have tail recursion

(define (ip-encapsulation dst-IP chk-idx compute-checksum len) ;; TODO why pass compute checksum as parameter ? (for the different upper protocols) why not calculate it in the upper protocol's encapsulation function ?
  (let ((ip-len (+ 20 len)))
    (u8vector-set! pkt ip-ttl ip-original-ttl)
    (set-ip-frag)
    (integer->pkt 0 ip-checksum 2)
    (u8vector-copy! dst-IP 0 pkt ip-dst-IP 4)
    (u8vector-copy! my-IP 0 pkt ip-src-IP 4)
    (integer->pkt (ip-identification) ip-ident 2)
    (integer->pkt ip-len ip-length 2)
    (u8vector-set! pkt ip-service 0)
    ;; set the version to IPv4 and the header size to 20 bytes (no options)
    (u8vector-set! pkt ip-version (+ (* 4 16) 5)) ;; TODO fixed header length, what about options ?
    (integer->pkt (reverse-checksum (compute-checksum)) chk-idx 2)
    ;; TODO good order for checksums ?
    (integer->pkt (reverse-checksum (compute-ip-checksum)) ip-checksum 2)
    (ethernet-encapsulation ip-len)))
;; TODO this should be connection agnostic (take the target ip from the original message), and not need to know the checksum function for the upper protocol
