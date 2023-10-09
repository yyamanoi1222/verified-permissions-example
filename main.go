package main

import (
	"fmt"
	"os"
	"github.com/aws/aws-sdk-go/service/verifiedpermissions"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/gin-gonic/gin"
)

type user struct {
	id string
}

type account struct {
	id string
}

type photo struct {
	id string
	owner string
}

const PERMISSION_ALLOW = "ALLOW"
var currentUser = user{id: "test"}
var currentAccount = account{id: "test"}
var sess = session.Must(session.NewSession())
var vp = verifiedpermissions.New(sess, aws.NewConfig().WithRegion("ap-northeast-1"))
var policyStoreId = os.Getenv("POLICY_STORE_ID")
var photos = map[string]photo{
	"1": photo{id: "1", owner: "test"},
	"2": photo{id: "2", owner: "test"},
	"3": photo{id: "3", owner: "other"},
}

type authorizedHandler interface {
	getAction(c *gin.Context) string
	getResource(c *gin.Context) (string, string)
	getHandler() gin.HandlerFunc
	getEntities(c *gin.Context) []*verifiedpermissions.EntityItem
}

type uploadPhotoHandler struct {}

func (h *uploadPhotoHandler) getAction(c *gin.Context) string {
	return "UploadPhoto"
}
func (h *uploadPhotoHandler) getResource(c *gin.Context) (string, string) {
	return "PhotoFlash::Photo", "dummy"
}
func (h *uploadPhotoHandler) getEntities(c *gin.Context) []*verifiedpermissions.EntityItem {
	id := "dummy"

	return []*verifiedpermissions.EntityItem{
		{
			Attributes: map[string]*verifiedpermissions.AttributeValue{
				"Account": &verifiedpermissions.AttributeValue{
					EntityIdentifier: &verifiedpermissions.EntityIdentifier{
						EntityType: aws.String("PhotoFlash::Account"),
						EntityId: aws.String(currentAccount.id),
					},
				},
			},
			Identifier: &verifiedpermissions.EntityIdentifier{
				EntityType: aws.String("PhotoFlash::User"),
				EntityId: aws.String(currentUser.id),
			},
			Parents: []*verifiedpermissions.EntityIdentifier{},
		},
		{
			Identifier: &verifiedpermissions.EntityIdentifier{
				EntityType: aws.String("PhotoFlash::Photo"),
				EntityId: aws.String(id),
			},
			Parents: []*verifiedpermissions.EntityIdentifier{
				{
					EntityType: aws.String("PhotoFlash::Account"),
					EntityId: aws.String(currentAccount.id),
				},
			},
		},
	}
}
func (h *uploadPhotoHandler) getHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// storageやDBへの書き込みをここで行う
		c.JSON(200, gin.H{
			"message": "upload photo successful!",
		})
	}
}

type viewPhotoHandler struct {}
func (h *viewPhotoHandler) getAction(c *gin.Context) string {
	return "ViewPhoto"
}
func (h *viewPhotoHandler) getResource(c *gin.Context) (string, string) {
	return "PhotoFlash::Photo", c.Param("id")
}
func (h *viewPhotoHandler) getEntities(c *gin.Context) []*verifiedpermissions.EntityItem {
	photo, ok := photos[c.Param("id")]
	if !ok {
		return []*verifiedpermissions.EntityItem{}
	}

	return []*verifiedpermissions.EntityItem{
		{
			Attributes: map[string]*verifiedpermissions.AttributeValue{
				"Account": &verifiedpermissions.AttributeValue{
					EntityIdentifier: &verifiedpermissions.EntityIdentifier{
						EntityType: aws.String("PhotoFlash::Account"),
						EntityId: aws.String(currentAccount.id),
					},
				},
			},
			Identifier: &verifiedpermissions.EntityIdentifier{
				EntityType: aws.String("PhotoFlash::User"),
				EntityId: aws.String(currentUser.id),
			},
			Parents: []*verifiedpermissions.EntityIdentifier{},
		},
		{
			Identifier: &verifiedpermissions.EntityIdentifier{
				EntityType: aws.String("PhotoFlash::Photo"),
				EntityId: aws.String(photo.id),
			},
			Parents: []*verifiedpermissions.EntityIdentifier{
				{
					EntityType: aws.String("PhotoFlash::Account"),
					EntityId: aws.String(photo.owner),
				},
			},
		},
	}
}
func (h *viewPhotoHandler) getHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// DBから取得した画像のURLを返す
		photoUrl := "https://dummy.com/" + c.Param("id") + "/dummy.jpg"
		c.JSON(200, gin.H{
			"image_url": photoUrl,
		})
	}
}

func authHandler(handler authorizedHandler) gin.HandlerFunc {
	return func(c *gin.Context) {
		rt, rs := handler.getResource(c)
		o, err := vp.IsAuthorized(&verifiedpermissions.IsAuthorizedInput{
			Action: &verifiedpermissions.ActionIdentifier{
				ActionId: aws.String(handler.getAction(c)),
				ActionType: aws.String("PhotoFlash::Action"),
			},
			Resource: &verifiedpermissions.EntityIdentifier{
				EntityType: aws.String(rt),
				EntityId: aws.String(rs),
			},
			Principal: &verifiedpermissions.EntityIdentifier{
				EntityType: aws.String("PhotoFlash::User"),
				EntityId: aws.String(currentUser.id),
			},
			Entities: &verifiedpermissions.EntitiesDefinition{
				EntityList: handler.getEntities(c),
			},
			PolicyStoreId: aws.String(policyStoreId),
		})
		if err != nil {
			fmt.Printf("err: %s \n", err)
			c.AbortWithStatus(400)
			return
		}

		if *o.Decision != PERMISSION_ALLOW {
			fmt.Printf("err: %v \n", o)
			c.AbortWithStatus(403)
			return
		}

		(handler.getHandler())(c)
		c.Next()
	}
}

func main() {
	r := gin.Default()

	r.POST("/photo/upload", authHandler(&uploadPhotoHandler{}))
	r.GET("/photo/:id", authHandler(&viewPhotoHandler{}))
	r.Run()
}
