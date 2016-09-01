#lang racket
(require charterm)
(provide begin-loading-bar
         display-bar-frame)

(define (begin-loading-bar bar-length)
  (with-charterm
   (charterm-clear-screen)
   (charterm-cursor 5 4)
   (charterm-display (make-string bar-length #\_))))

(define (display-bar-frame bar-len i total-len)
  (with-charterm
   (charterm-cursor 1 5)
   (charterm-display (ceiling (/ i (/ total-len bar-len))))
   (charterm-bold)
   (charterm-cursor 5 5)
   (charterm-display (make-string (ceiling (/ i (/ total-len bar-len))) #\=))))
