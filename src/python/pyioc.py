import os
import sys
from lxml import etree


class Context(object):
	
	def __init__(self, document, search, type):
		self.document = document
		self.search = search
		self.type = type

	def getDocument(self):
		return self.document

	def getSearch(self):
		return self.search

	def getType(self):
		return self.type

class Content(object):
	def __init__(self,type, value):
		self.type = type
		self.value = value

	def getType(self):
		return self.type

	def getValue(self):
		return self.value

class IndicatorItem(object):
	"""
	Class representing an individual piece of threat intelligence
	that when combined with other items under an indicator can be used
	for determination that a threat is present.
	"""
	def __init__(self, id, condition, context, content):
		self.id = id
		self.condition = condition
		self.context = context
		self.content = content

	def __str__(self):
		return ("Indicator Item:\n" + "  ID: " + self.id + "\tCondition: " + self.condition + "\tContext Doc: " 
			+ self.context.getDocument() + "\tContext Search: " + 
			  self.context.getSearch() + "\tContent type: " + self.content.getType() 
			+ "\tContent Value: " + self.content.getValue())

	def getId(self):
		return self.id
	
	def getCondition(self):
		return self.condition

	def getContext(self):
		return self.context

	def getContent(self):
		return self.content
		

class Indicator(object):
	"""
	Class that represents the threat intelligence defining an indicator.
	The indicator is made up of indicator items or other full indicators required to define the indicator.
	"""
	def __init__(self, id, operator,parent=None):
		self.indicatorItems = []
		self.subIndicators = []
		self.indicatorId = id
		self.operator = operator
		self.parent = parent

	def __str__(self):
		pad = ""
		if self.parent is None:
			pad = ""
		else:
			pad = "\t"
			p = self.parent
			while p.parent is not None:
				pad += "\t"
				p = p.parent	
		strval = pad + "Indicator: "
		strval += pad + "\tID: " + self.indicatorId 
		strval += "\n"
		strval += pad + "\tOperator: " + self.operator + "\n"
		for item in self.indicatorItems:
			strval += pad + "\t" + str(item) + "\n"
		for indicator in self.subIndicators:
			strval += str(indicator) + "\n"
		return strval

	def setParent(self,parentIndicator):
		self.parent = parentIndicator

	def getParent(self):
		return self.parent

	def addIndicator(self,newIndicator):
		self.subIndicators.append(newIndicator)
		newIndicator.setParent(self)
	
	def addIndicatorItem(self, newItem):
		self.indicatorItems.append(newItem)

 
class PyIOC(object):
	"""
	Class that represents a parsed IOC file
	"""

	def __init__(self, fileName):
		self.tree = None
		self.root = None
		self.short_description = None
		self.description = None
		self.links = []
		self.definition = []
		self.authored_by = None
		self.authored_date = None
		self.fileName = fileName
		self.tree = self.read_ioc_file(fileName)
		if self.tree is None:
			return
		self.root = self.tree.getroot()
		if not self.parseIOC(self.root):
			return	
		print(self)


	def __str__(self):
		strval =  ("Short Description: " + self.short_description +
			"\nDescription: " + self.description  + 
			"\nAuthored By: " + self.authored_by + 
			"\nAuthored Date: " + self.authored_date +
			"\n")
		for indicator in self.definition:
			strval += str(indicator) + "\n"
		return strval

	
	def read_ioc_file(self,fileName):
		try:
			parser = etree.XMLParser(remove_blank_text=True)
			return etree.parse(fileName,parser)
		except IOError:
			print("Failed to open file " + fileName)
			return None
		except etree.XMLSyntaxError:
			print("Unable to parse XML in IOC file " + fileName)
			return None

	def parseIOC(self, root):
		rc = False
		name = etree.QName(root.tag)
		if name.localname.lower() != 'ioc':
			print("Bad IOC root node.")
			return rc
		del name
		for child in root:
			name = etree.QName(child.tag)
			if name.localname.lower() == 'short_description':
				self.short_description = child.text
			elif name.localname.lower() == 'description':
				self.description = child.text
			elif name.localname.lower() == 'authored_by':
				self.authored_by = child.text
			elif name.localname.lower() == 'authored_date':
				self.authored_date = child.text
			elif name.localname.lower() == 'links':
				pass
			elif name.localname.lower() == 'definition':
				rc = self.parseDefinition(child)
			del name
		print("rc = " + str(rc))
		return rc

	def parseDefinition(self, defNode):
		rc = False
		for item in defNode:
			name = etree.QName(item.tag)
			if name.localname.lower() == 'indicator':
				indicator = self.parseIndicator(item)
				if indicator is not None:
					print("added indicator")
					self.definition.append(indicator)
					rc = True
		return rc

	def parseIndicator(self, indicatorNode, parent=None):
		operator = indicatorNode.get('operator')
		indId = indicatorNode.get('id')
		indicator = Indicator(indId,operator,parent)
		# indicators will contain indicator items and possible sub indicators.
		for child in indicatorNode:
			name = etree.QName(child.tag)
			if name.localname.lower() == 'indicatoritem':
				item = self.parseIndicatorItem(child)
				if item is not None:
					print("added item to indicator")
					indicator.addIndicatorItem(item)
			elif name.localname.lower() == 'indicator':
				subIndicator = self.parseIndicator(child,indicator)
				if subIndicator is not None:
					print("added sub indicator")
					indicator.addIndicator(subIndicator)	
		return indicator

	def parseIndicatorItem(self, indicatorItemNode):
		itemId = indicatorItemNode.get('id')
		itemCondition = indicatorItemNode.get('condition')
		contextDocument = None
		contextSearch = None
		contextType = None
		contentType = None
		contentValue = None
		# grab the context and content children nodes.
		for child in indicatorItemNode:
			name = etree.QName(child.tag)
			if name.localname.lower() == 'context':
				contextDocument = child.get('document')
				contextSearch = child.get('search')
				contextType = child.get('type')	
			elif name.localname.lower() == 'content':
				contentType = child.get('type')
				contentValue = child.text
		context = Context(contextDocument, contextSearch, contextType)
		content = Content(contentType, contentValue)
		indicatorItem = IndicatorItem(itemId, itemCondition, context, content)	
		return indicatorItem	
		
if __name__ == '__main__':
		ioc = PyIOC(sys.argv[1])

