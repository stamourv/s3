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
  (set! ip-opt-len (- (get-ip-hdr-len) 20)) ; a normal header is 20 bytes
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
(define (compute-ip-checksum)
  (pkt-checksum (eth-offset 0)
                (+ (eth-offset 0) 20)
                (compute-ip-options-checksum))) ;; TODO why not just calculate the checksum of the whole header + options at the same time ?
(define (compute-ip-options-checksum)
  (let* ((start (+ (eth-offset 0) 20)))
    (pkt-checksum start (+ start ip-opt-len) 0)))

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
    (integer->pkt-2 0 ip-checksum)
    (copy-u8->pkt-4 ip-dst-IP dst-IP) ;; TODO should be a u8vector or a ref ?
    (copy-u8->pkt-4 ip-src-IP my-IP)
    (integer->pkt-2 (ip-identification) ip-ident)
    (integer->pkt-2 ip-len ip-length)
    (u8vector-set! pkt ip-service 0)
    ;; set the version to IPv4 and the header size to 20 bytes (no options)
    (u8vector-set! pkt ip-version (+ (* 4 16) 5)) ;; TODO fixed header length, what about options ?
    (integer->pkt-2 (reverse-checksum (compute-checksum)) chk-idx)
    ;; TODO good order for checksums ?
    (integer->pkt-2 (reverse-checksum (compute-ip-checksum)) ip-checksum)
    (ethernet-encapsulation ip-len)))
;; TODO this should be connection agnostic (take the target ip from the original message), and not need to know the checksum function for the upper protocol
