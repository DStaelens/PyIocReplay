import os
import sys
import logging

class IndicatorGenerator(object):
	
	def __init__(self, definition):
		self.definition = definition
		logging.basicConfig(filename='indicators.log', format='%(asctime)s %(message)s', level=logging.INFO)
		
	def generateIndicators(self):
		fileNameIndicators = []
		""" run through the indicators and generate a list of things to create.
			Out of time for this paper, so for now just generate filename indicators for
			getting the proof of concept across....
			If this turns into a real project such as a capstone, this will be fleshed out
			appropriately.
		"""
		fileNameIndicators = self.getIndicatorItemType('FileItem/FileName',self.definition[0])
		for fileIndicator in fileNameIndicators:
			open(fileIndicator,'a').close()
			logging.info("Created filename indicator " + fileIndicator)
		
	def getIndicatorItemType(self,type, indicator):
		""" recursively return all indicator items with a search type of 'type' """
		indicators = []
		for indItem in indicator.indicatorItems:
			if indItem.getContext().getSearch() == type:
				indicators.append(indItem.getContent().getValue())
		for subIndicator in indicator.subIndicators:
			indicators.extend(self.getIndicatorItemType(type,subIndicator))
		return indicators