package net.passioncloud.secure.configuration;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import net.passioncloud.secure.domain.exception.NotFoundException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import javax.servlet.http.HttpServletRequest;
import javax.validation.ValidationException;
import java.nio.file.AccessDeniedException;
import java.util.*;
import java.util.stream.Collectors;

@ControllerAdvice
public class GlobalExceptionHandler {
    private final Logger logger = LogManager.getLogger();

    @ExceptionHandler(NotFoundException.class)
    public ResponseEntity<ApiCallError<String>> handleNotFoundException(HttpServletRequest request,
                                                                        NotFoundException e) {
        logger.error("NotFoundException {}\n", request.getRequestURI(), e);
        return ResponseEntity
                .status(HttpStatus.NOT_FOUND)
                .body(new ApiCallError<>("Not found exception", List.of(e.getMessage())));
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiCallError<String>> handleBadCredentialsException(HttpServletRequest request,
                                                                            BadCredentialsException e) {
        logger.error("BadCredentialsException {}\n", request.getRequestURI(), e);
        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(new ApiCallError<>("BadCredentialsException", List.of(e.getMessage())));
    }

    @ExceptionHandler(ValidationException.class)
    public ResponseEntity<ApiCallError<String>> handleValidationException(HttpServletRequest request,
                                                                          ValidationException e) {
        logger.error("ValidationException {}\n", request.getRequestURI(), e);
        return ResponseEntity
                .badRequest()
                .body(new ApiCallError<>("Validation exception", List.of(e.getMessage())));
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<ApiCallError<String>> handleMissingServletRequestParameterException(HttpServletRequest request,
                                                                                              MissingServletRequestParameterException e) {
        logger.error("MissingServletRequestException {}\n", request.getRequestURI(), e);
        return ResponseEntity
                .badRequest()
                .body(new ApiCallError<>("MissingServletRequestException {}\n", List.of(e.getMessage())));
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<ApiCallError<Map<String, String>>> handleMethodArgumentTypeMismatchException(HttpServletRequest request,
                                                                                                       MethodArgumentTypeMismatchException e) {
        logger.error("MethodArgumentTypeMismatchException {}\n", request.getRequestURI(), e);
        Map<String, String> details = new HashMap<>();
        details.put("paramName", e.getName());
        details.put("paramValue", Optional.ofNullable(e.getValue()).map(Object::toString).orElse(""));
        details.put("errorMessage", e.getMessage());
        return ResponseEntity
                .badRequest()
                .body(new ApiCallError<>("MethodArgumentTypeMismatchException", List.of(details)));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiCallError<Map<String, String>>> handleMethodArgumentNotValidException(HttpServletRequest request,
                                                                                                   MethodArgumentNotValidException e) {
        logger.error("MethodArgumentNotValidException {}\n", request.getRequestURI(), e);
        List<Map<String, String>> details = e.getBindingResult()
                .getFieldErrors()
                .stream().map(fieldError -> {
                    Map<String, String> detail = new HashMap<>();
                    detail.put("objectName", fieldError.getObjectName());
                    detail.put("field", fieldError.getField());
                    detail.put("rejectedValue", "" + fieldError.getRejectedValue());
                    detail.put("errorMessage", fieldError.getDefaultMessage());
                    return detail;
                })
                .collect(Collectors.toList());
        return ResponseEntity
                .badRequest()
                .body(new ApiCallError<>("MethodArgumentNotValidException", details));
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiCallError<String>> handleAccessDeniedException(HttpServletRequest request,
                                                                            AccessDeniedException e) {
        logger.error("AccessDeniedException {}\n", request.getRequestURI(), e);
        return ResponseEntity
                .status(HttpStatus.FORBIDDEN)
                .body(new ApiCallError<>("AccessDeniedException", List.of(e.getMessage())));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiCallError<String>> handleInternalServerError(HttpServletRequest request, Exception e) {
        logger.error("InternalServerErrorException {}\n", request.getRequestURI(), e);
        return ResponseEntity
                .internalServerError()
                .body(new ApiCallError<>("InternalServerErrorException", List.of(e.getMessage())));
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ApiCallError<T> {
        private String message;
        private List<T> details;
    }
}
