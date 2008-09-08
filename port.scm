;;;; Lysiane Bouchard - Vincent St-Amour
;;;; port.scm

;;;  - port structure description and operations
;;;  - port configuration description and operations
;;;  - port binding functions
;;;  - port number conversion functions


;; a port structure is a pair (conf . conns)
;; the car is a port configuration stucture, described below
;; the cdr is a list containing all the active connections on this port
(define (add-conn-to-curr-port conn)
  (set-cdr! curr-port (cons conn (cdr curr-port)))) ;; TODO inline ? would leak the specification, but still
(define (get-curr-conns) (cdr curr-port)) 

;; conf structures are represented as vectors :
;; -0: port number (integer)
;; -1: maximum number of connections (integer)
;;     applies only to TCP
;; -2: filter function (function)
;;     this function is a predicate that returns true if the application
;;     accepts the connection. it takes the destination's ip, the source's ip
;;     (as length 4 u8vectors) and the source's port (as an integer) as
;;     arguments
;; -3: reception function (function)
;;     TCP :
;;     this function takes the connection structure as argument and is called
;;     when the connection is created by the stack. The application can then
;;     access the input and output buffers of the connection at any time.
;;     UDP :
;;     this function takes the source IP and the source port number of the
;;     datagram along with a vector containing the data of the datagram.
;;     the application handles the datagram in this function, and can send a
;;     reply in it
(define conf-portnum   0)
(define conf-max-conns 1)
(define conf-filter    2)
(define conf-reception 3)
(define (conf-ref port i) (vector-ref (car port) i))


;;; server management

(define (search-port portnum ports)
  (memp (lambda (p) (= portnum (conf-ref p conf-portnum))) ports))

;; homologuous to BSD sockets', to be called from the application
;; takes the port number, the maximum simultaneous number of connections and
;; application filter and linker functions
(define (tcp-bind portnum max-conns filter linker)
  (if (search-port portnum tcp-ports)
      #f
      (begin
	(set! tcp-ports (cons (cons (vector portnum max-conns filter linker)
				    '())
			      tcp-ports))
	#t)))
;; TODO can we detach a port form a ports ? if the application terminates, for example
;; TODO maybe, if we try to bind a port that is already bound, get rid of the old server structure ?

;; similar to TCP's, but doesn't take the maximum number of connections
(define (udp-bind portnum filter linker)
  (if (search-port portnum udp-ports)
      #f
      (begin
	(set! udp-ports (cons (cons (vector portnum 0 filter linker) '())
			      udp-ports))
	#t)))

;; does the ip datagram pass the filter of the current port ?
(define (pass-app-filter? src-portnum-idx port)
  (let ((dst-ip (u8vector-ref-field pkt ip-destination-ip 4)) ; length 4 u8vector
        (src-ip (u8vector-ref-field pkt ip-source-ip 4)) ; length 4 u8vector
        (src-portnum-ref (pkt-ref-2 src-portnum-idx)))    ; integer
    ((conf-ref port conf-filter) dst-ip src-ip src-portnum-ref)))


;;; simple conversion functions
(define (portnum->u8vector n)
  (u8vector (quotient n 256) (modulo n 256)))
(define (u8vector->portnum v)
  (+ (* 256 (u8vector-ref v 0)) (u8vector-ref v 1)))
