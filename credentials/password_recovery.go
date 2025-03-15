package main

import (
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "fmt"
    "io"
    "log"
    "net/smtp"
)

const otpLength = 6
const otpChars = "0123456789"

func generateOTP() string {
    otp := make([]byte, otpLength)
    _, err := rand.Read(otp)
    if err != nil {
        log.Fatal(err)
    }
    for i := 0; i < otpLength; i++ {
        otp[i] = otpChars[otp[i]%byte(len(otpChars))]
    }
    return string(otp)
}

func sendEmail(to, subject, body string) error {
    from := "your_email@example.com"
    password := "your_password"
    smtpHost := "smtp.example.com"
    smtpPort := "587"

    msg := "From: " + from + "\n" +
        "To: " + to + "\n" +
        "Subject: " + subject + "\n\n" +
        body

    auth := smtp.PlainAuth("", from, password, smtpHost)
    return smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{to}, []byte(msg))
}

func recoverPassword(username, email string) {
    otp := generateOTP()
    subject := "Password Recovery OTP"
    body := fmt.Sprintf("Your OTP for password recovery is: %s", otp)

    err := sendEmail(email, subject, body)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("OTP sent to %s\n", email)

    var inputOTP string
    fmt.Print("Enter the OTP: ")
    fmt.Scan(&inputOTP)

    if inputOTP == otp {
        fmt.Println("OTP verified successfully. You can now reset your password.")
    } else {
        fmt.Println("Invalid OTP. Password recovery failed.")
    }
}

func main() {
    username := "example_user"
    email := "user_email@example.com"
    recoverPassword(username, email)
}