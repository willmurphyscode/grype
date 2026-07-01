package main

import "github.com/gin-gonic/gin"

func main() {
	// gin.Default() installs the vulnerable Logger middleware; reference the Logger
	// entrypoints directly too so the vulnerable symbols are compiled into the binary.
	r := gin.Default()
	_ = gin.Logger()
	r.Use(gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string { return param.Path }))
	r.GET("/ping", func(c *gin.Context) { c.JSON(200, gin.H{"message": "pong"}) })
	_ = r.Run(":8080")
}
