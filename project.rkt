#lang rackjure
(require sha net/url
         net/http-client json
         sugar net/uri-codec)

(define (read-files-sha256 paths)
  (list paths
        (string-join (map (λ (path)
                            (with-input-from-file path
                              (λ ()
                                (~> path file-size read-bytes sha256 bytes->hex-string))))
                          paths) ",")))

(define (chunk n lst) (break-at lst (range 0 (length lst) n)))

(define (read-directory-sha256 dir)
  (define fs/ds (map #λ(build-path dir (path->string %)) (directory-list dir)))
  (map read-files-sha256 (chunk 25 (filter file-exists? fs/ds))))

(define (virustotal-test names sha)
  (define API-KEY "6af4e84e123608ef1bb2ffd2cda4dba822c20cf730afb7248efefd300ac8259e")
  (define-values (status-code header inport)
    (http-sendrecv
     "www.virustotal.com"
     "/vtapi/v2/file/report"
     #:method "POST"
     #:data (alist->form-urlencoded
             (list (cons 'apikey API-KEY)
                   (cons 'resource sha)))))
  (list names (read-json inport)))

(define (format-hash h [c "\033[0m"])
  (string-join (map #λ(string-append "\033[0m" %1 ": " %2 c) (hash-keys h) (hash-values h)) "\n"))

(define (draw-box inner-text)
  (define (remove-colors s)
    (~> s (string-replace "\033[91m" "")
        (string-replace "\033[92m" "")
        (string-replace "\033[1m" "")
        (string-replace "\033[0m" "")))
  (define lst (string-split inner-text "\n"))
  (define wall-len (+ 2 (apply max (map (compose string-length remove-colors) lst))))
  (define wall+text (map (lambda (x)
                           (let* ([diff (- wall-len (string-length
                                                     (remove-colors x)) 1)]
                                  [spcs (make-string diff #\space)])
                             (string-append "│ " x spcs "│"))) lst))
  (displayln (string-append "┌" (make-string wall-len (first (string->list "─"))) "┐"))
  (for-each displayln wall+text)
  (displayln (string-append "└" (make-string wall-len (first (string->list "─"))) "┘")))

(define (byte-format n)
  (string-append (number->string n) "B"))

(define (gen-positives p t) (format "Positives: ~a% (~a/~a)"
                                    (ceiling (* 100 (/ p t))) p t))
(define (basic-attrs name verdict) (hash "Date Scanned" (hash-ref verdict 'scan_date)
                                         "Filename" (path->string name)
                                         "Size" (byte-format (file-size name))))

(define (display-verbose-verdict name verdict)
  (define attrs (basic-attrs name verdict))
  (define p (hash-ref verdict 'positives))
  (define t (hash-ref verdict 'total))
  (define positives (gen-positives p t))
  (displayln (string-append (format-hash attrs) "\n"))
  (for ([vtn (hash-keys (hash-ref verdict 'scans))]
        [vt (hash-values (hash-ref verdict 'scans))])
    (define color (if (hash-ref vt 'detected)
                      "\033[91m"
                      "\033[92m"))
    (display color)
    (draw-box (format "\033[0mVirus Scanner: ~a~a\n\033[0m└ Verdict: \033[1m~a\033[0m~a"
                      vtn color (hash-ref vt 'result) color))
    (displayln "\033[0m")
    (displayln ""))
  (displayln positives))

(define (display-file-verdict name verdict [verbose? #t])
  (when (= (hash-ref verdict 'response_code) 1)
    (if verbose?
      (display-verbose-verdict name verdict)
      (let* ([attrs (basic-attrs name verdict)]
             [p (hash-ref verdict 'positives)]
             [t (hash-ref verdict 'total)]
             [positives (gen-positives p t)])
        (define color (if (> p 0)
                          "\033[91m"
                          "\033[92m"))
        (display color)
        (draw-box (string-append "\033[0m" (format-hash attrs color) color "\n" "\033[1m" positives color))
        (displayln "\033[0m")
        (displayln "")))))

(define file-or-dir (command-line #:args (file-or-dir)
                                  (string->path file-or-dir)))

(define branch (list (file-exists? file-or-dir)
                     (directory-exists? file-or-dir)))

(unless (apply #λ(or %1 %2) branch)
  (displayln (format "Can't find file or directory '~a'"
                     (path->string file-or-dir))))

(define shas (if (and (first branch) (not (second branch)))
                 (list (read-files-sha256 (list file-or-dir)))
                 (read-directory-sha256 file-or-dir)))
(define response (map (λ (names-sha i)
                        (define vt (apply virustotal-test names-sha))
                        (define fvt (if (list? (first vt)) (first vt) (list (first vt))))
                        (define svt (if (list? (second vt)) (second vt) (list (second vt))))
                        (map display-file-verdict fvt svt
                             (make-list (length svt) (= (length svt) 1)))
                        (sleep 15))
                      shas (range 0 (length shas))))
