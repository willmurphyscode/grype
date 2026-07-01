package main

import "github.com/gin-gonic/gin"

func main() {
	// gin.New() does NOT install the Logger middleware (that is gin.Default()).
	// This program never references Default/Logger/LoggerWith*, so those symbols
	// should be dead-code-eliminated from the binary.
	r := gin.New()
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "pong"})
	})
	_ = r.Run(":8080")
}
