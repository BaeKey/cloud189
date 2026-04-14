package main

import "encoding/xml"

type MultiStatus struct {
	XMLName   xml.Name   `xml:"D:multistatus"`
	XMLNS     string     `xml:"xmlns:D,attr"`
	Responses []Response `xml:"D:response"`
}

type Response struct {
	Href     string     `xml:"D:href"`
	Propstat []Propstat `xml:"D:propstat"`
}

type Propstat struct {
	Prop   Prop   `xml:"D:prop"`
	Status string `xml:"D:status"`
}

type Prop struct {
	ResourceType     *ResourceType `xml:"D:resourcetype"`
	DisplayName      string        `xml:"D:displayname,omitempty"`
	GetContentLength string        `xml:"D:getcontentlength,omitempty"`
	GetLastModified  string        `xml:"D:getlastmodified,omitempty"`
	CreationDate     string        `xml:"D:creationdate,omitempty"`
	GetContentType   string        `xml:"D:getcontenttype,omitempty"`
	GetETag          string        `xml:"D:getetag,omitempty"`
}

type ResourceType struct {
	Collection *struct{} `xml:"D:collection,omitempty"`
}
