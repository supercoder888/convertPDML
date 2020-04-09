#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys, os, codecs, random

debug = True
#debug = False

#[ip:port] = color
servers = {}
#[ip] = color
clients = {}

def print_help(output):
  output.write("""
  Wireshark PDML Converter for WhatsApp

  Usage:
    """+os.path.basename(sys.argv[0])+""" INPUT
      INPUT  - input .xml file
  """)
  
def randomColor():  
  r = lambda: random.randint(0,255)
  return '#%02X%02X%02X' % (r(),r(),r())
  
def figureOutDirection(srcIP, srcPort, dstIP, dstPort, message):
  if(srcPort == u'5222' or srcPort == u'443'):
    message.serverAddr = '%s:%s' % (srcIP, srcPort)
    message.clientAddr = '%s:%s' % (dstIP, dstPort)
    message.direction = 'server2client'
    if(not(message.serverAddr in servers.keys())):
      servers[message.serverAddr] = randomColor()
    if(not(dstIP in clients.keys())):
      clients[dstIP] = randomColor()
    return
  if(dstPort == u'5222' or dstPort == u'443'):
    message.serverAddr = '%s:%s' % (dstIP, dstPort)
    message.clientAddr = '%s:%s' % (srcIP, srcPort)
    message.direction = 'client2server'
    if(not(message.serverAddr in servers.keys())):
      servers[message.serverAddr] = randomColor()
    if(not(srcIP in clients.keys())):
      clients[srcIP] = randomColor()
    return
  message.direction = 'unknown'
  return
#class Packet
#  number = None  

class Node:  
  def __init__(self):
    self.type = None # node or attribute
    self.name = None
    self.parent = None
    self.depth = 0
    self.nodes = []
    self.attributes = []
    self.key = None
    self.value = None
  
  def Cleanse(self):
    for node in self.nodes:
      node.Cleanse()
    if(len(self.nodes) == 1 and self.nodes[0].key == None):
      if(debug):
        sys.stderr.write("cleansing\n")
      self.nodes = []
      
  def GetTypes(self, outList):
    if(self.type == 'attribute'):
      if(self.key == u'resource' and not(self.key in outList)):
        outList.append(self.key)
    if(self.type == 'node'):      
      if(not(self.key in outList) and self.key != None): #if(self.key == u'stream:features' or self.key == u'auth' or self.key == u'challenge' or self.key == u'call' or self.key == u'ack' or self.key == u'offer' or self.key == u'relay' or self.key == u'receipt' or self.key == u'preaccept' or self.key == u'audio' or self.key == u'p2p' or self.key == u'srtp' or self.key == u'stream:error' or self.key == u'response' or self.key == u'success' or self.key == u'presence' or self.key == u'ib' or self.key == u'iq' and not(self.key in outList)):
        outList.append(self.key)
    for node in self.nodes:
      node.GetTypes(outList)
    for attribute in self.attributes:
      attribute.GetTypes(outList)
  
  def ToHTML(self, indent):
    self.Cleanse()
    val = u''
    tag = u''
    if(self.type == None):
      tag = u'None'
    elif(self.type == 'node'):
      if(self.key != None):
        tag = u'&lt;%s' % self.key
      else:
        if(len(self.nodes) == 0 and len(self.attributes) == 0 and self.value == None):
          return val
        tag = u'&lt;stream:stream'
      for i in range(0, indent):
        val += u'&nbsp;&nbsp;&nbsp;&nbsp;'
      val += tag
    elif(self.type == 'attribute'):
      val += u' %s="%s"' % (self.key, self.value)
      return val
    else:
      val += u'UNKNOWN: %s' % self.type
    for attribute in self.attributes:
      #sys.stderr.write('attribute at %d\n' % id(attribute))
      val += attribute.ToHTML(0)
    if(len(self.nodes) > 0):
      val += u'&gt;'
      for node in self.nodes:    
        val += u'%s<br>\n' % node.ToHTML(indent+1)
      for i in range(0, indent):
        val += u'&nbsp;&nbsp;&nbsp;&nbsp;'
      val += u'&lt;/%s&gt;' % (tag[4:])
    elif(self.value != None):
      val += u'&gt;<br>\n'
      if(self.key == u'te' and len(self.value) == 12):
        for i in range(0, indent+1):
          val += u'&nbsp;&nbsp;&nbsp;&nbsp;'
        val += u'%d.%d.%d.%d:%d (%s)<br>\n' % (int(self.value[0:2], 16), int(self.value[2:4], 16), int(self.value[4:6], 16), int(self.value[6:8], 16), int(self.value[8:12], 16), self.value)
      else:
        for i in range(0, indent+1):
          val += u'&nbsp;&nbsp;&nbsp;&nbsp;'
        val += u'%s<br>\n' % self.value
      for i in range(0, indent):
        val += u'&nbsp;&nbsp;&nbsp;&nbsp;'
      val += u'&lt;/%s&gt;' % (tag[4:])
    else:
      val += u' /&gt;'
    return val
        
  
class Message: 
  def __init__(self, packetNumber, messageNumber):
    self.type = None
    self.packetNumber = packetNumber;
    self.messageNumber = messageNumber
    self.clientAddr = None
    self.serverAddr = None
    self.direction = None # server2client or client2server
    self.nodes = []
  
  def ToHTML(self):
    #val = u'%s &lt;' % self.packetNumber
    tag = u''
    #if(self.type == None):
     # tag = u'stream:stream'
    #else:
    #  tag = u'%s' % type
    #val += tag
    val = u''
      
    if(len(self.nodes) > 0):
      typeList = []
      for node in self.nodes:
        node.GetTypes(typeList)
      if(len(typeList) == 0):
        self.type = u'<i>unknown</i>'
      else:
        self.type = u', '.join(typeList)
      val += u'''
      <tr>
		<td rowspan="2"> [%s] </td>''' % self.packetNumber
      val += '''
		<td rowspan="2" class="endpoint" style="background-color: %s;" onMouseOver="highlightEndpoint(this, '%s')" onMouseOut="unhighlightEndpoint(this, '%s')">  </td>''' % (clients[self.clientAddr[:self.clientAddr.index(':')]], self.clientAddr[:self.clientAddr.index(':')], self.clientAddr[:self.clientAddr.index(':')])
      val +='''
        <td><div class="clickable" onClick="toggleVisibility('%s_%d')" id="%s_%d_button"> [+] %s </div>''' % (self.packetNumber, self.messageNumber, self.packetNumber, self.messageNumber, self.type)
      val += '''
          <div id="%s_%d" class="info hidden">''' % (self.packetNumber, self.messageNumber)
      for node in self.nodes:
        val += u'\n%s<br>' % node.ToHTML(0)
      val += '''
          </div>
        </td>
		<td rowspan="2" class="endpoint" style="background-color: %s;" onMouseOver="highlightEndpoint(this, '%s')" onMouseOut="unhighlightEndpoint(this, '%s')">  </td>
	  </tr>''' % (servers[self.serverAddr], self.serverAddr, self.serverAddr)
      if(self.direction == 'client2server'):
        val += '''
      <tr><td class="arrow"> = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = &#10095; &#10095; &#10095; </td></tr>
        ''' 
      if(self.direction == 'server2client'):
        val += '''
      <tr><td class="arrow"> &#10094; &#10094; &#10094; = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = </td></tr>
        ''' 
    return val
  
def convertPDML(inputFilename):
  global debug
  sys.stderr.write("input:  %s\n" % inputFilename)
  outputFilename = inputFilename[:-3] + "html"
  sys.stderr.write("output: %s\n" % outputFilename)
  
  UTF8Writer = codecs.getwriter('utf8')
  UTF8Reader = codecs.getreader('utf8')
  sys.stdout = UTF8Writer(sys.stdout)
  sys.stderr = UTF8Writer(sys.stderr)
  inputFile = open(inputFilename, "r")
  inputFile = UTF8Reader(inputFile)
  inputFileSize = os.path.getsize(inputFile.name)
  print inputFile.tell(), inputFileSize
  if(inputFileSize > 8000):
    debug = False
  #nodes = 0
  #lines = 0

  sys.stdout.write("parsing input...\n")

  outputFile = open(outputFilename, "w")
  outputFile = UTF8Writer(outputFile)
  outputFile.write('''<!DOCTYPE html>
<html>
  <head>
  <meta http-equiv="content-type" content="text/html; charset=utf-8">
  <title>%s</title>''' % inputFilename[:-3])
  outputFile.write('''
  <style type="text/css">
    .info {
	  background-color: #ffffa0;
	  text-align: left;
	  font-family: courier;
	  font-weight: bold;
	  font-size: 80%; 
	  width: 1000px;
	  word-wrap: break-word; }
	.hidden { visibility: hidden; display: none; }
	.visible { visibility: visible; display: block; }
	.clickable { cursor: pointer; }
	td {text-align: center;}
	.endpoint { width: 10px; }
    .endpointTable { 
      width: 300px;
      position: fixed;
      right: 0;
      float: right;
      border: black 1px solid; 
      border-radius: 10px;
      padding: 10px; 
      font-family: helvetica;
      font-weight: bold;
      font-size: 14pt; }
    .arrow {
      font-family: courier;
      font-weight: bold; }
    th.rotate {
      -ms-transform: rotate(90deg); /* IE 9 */
      -webkit-transform: rotate(90deg); /* Chrome, Safari, Opera */
      transform: rotate(90deg); 
      z-index: -1; }
    .shadow {
      border-style: solid;
      border-width: 5px;
    }
  </style>
  <script type="text/javascript">
    function toggleVisibility(id){
	  obj = document.getElementById(id);
	  if(obj == null){
		  alert(id+' not found');
		  return;
	  }
	  if(obj.className == "info hidden"){
		  obj.className = "info visible";
          link = document.getElementById(id+'_button');
          link.innerHTML = ' [-]'+link.innerHTML.substring(4);
      }
	  else if(obj.className == "info visible"){
		  obj.className = "info hidden";
          link = document.getElementById(id+'_button');
          link.innerHTML = ' [+]'+link.innerHTML.substring(4);
      }
	  return;
	}
    
    function expandAll(){
        var tds = document.getElementsByTagName('div');
        for (var index in tds) {
            var td = tds[index];
            if(td.className == "clickable"){
                td.innerHTML = ' [-]'+td.innerHTML.substring(4);
            }
        }
        var divs = document.getElementsByTagName('div');
        for (var index in divs) {
            var div = divs[index];
            if(div.className == "info hidden"){
                div.className = "info visible";
            }
        }
    }
    
    function colapseAll(){
        var tds = document.getElementsByTagName('div');
        for (var index in tds) {
            var td = tds[index];
            if(td.className == "clickable"){
                td.innerHTML = ' [+]'+td.innerHTML.substring(4);
            }
        }
        var divs = document.getElementsByTagName('div');
        for (var index in divs) {
            var div = divs[index];
            if(div.className == "info visible"){
                div.className = "info hidden";
            }
        }
    }
    
    function highlightEndpoint(td, server){
      td.className = "endpoint shadow";
      span = document.getElementById(server);
      span.className = "shadow";
    }
    
    function unhighlightEndpoint(td, server){
      td.className = "endpoint";
      span = document.getElementById(server);
      span.className = "";
    }
  </script>
  </head>
  <body>
    <a href="#" onClick="expandAll()" style="font-family: courier;">[+] expand all</a><br>
    <a href="#" onClick="colapseAll()" style="font-family: courier;">[-] colapse all</a>
	<table border="0" cellspacing="0">
      <tr>
        <th><br><br><br>packet<br><br></th>
        <th class="rotate">client</th>
        <th class="rotate">message</th>
        <th class="rotate">server</th>
      </tr>
''')
  
  packetNumber = 0
  messageNumber = 0
  srcIP = None
  srcPort = None
  dstIP = None
  dstPort = None
  state = "UNKNOWN"
  parentObject = None
  currentObject = None
  parentMessage = None
  messages = []
  lines = 1
  
  for line in inputFile:
    #sys.stderr.write('line %d\n' % lines)
    #if(type(currentObject) == Node):
    #  sys.stderr.write('currentObject Node\n')
    #elif(type(currentObject) == Message):
    #  sys.stderr.write('currentObject Message\n')
    #elif(type(currentObject) == type(None)):
    #  sys.stderr.write('currentObject None\n')
    #else:
    #  sys.stderr.write('currentObject UNKNOWN\n')
    if(debug):
      sys.stderr.write('before: currentObject %s %s\n' % (currentObject.__class__.__name__, currentObject.type if (currentObject.__class__.__name__ == 'Node') else u''))
      sys.stderr.write('before: parentObject  %s %s\n' % (parentObject.__class__.__name__, parentObject.type if (parentObject.__class__.__name__ == 'Node') else u''))
    lines += 1
    line = line.strip()
    tokens = line.split(' ')
    #print tokens
    if(tokens[0] == u'<packet'):
      packetNumber = None
      state = "packet_begin"
      #nodes += 1
      if(tokens[-1][-2:] == u'/>'):
        # single line node, not interesting
        pass
      else:
        # processing node's lat&lon
        #nodeLineToKeyValuePairs(tokens[1:], values)
        pass
    elif(tokens[0] == u'</packet>'):
      # process gathered data
      for message in messages:
        #sys.stdout.write("%s\n" % message.ToHTML());
        outputFile.write(message.ToHTML())
      # reset
      packetNumber = 0
      messageNumber = 0
      srcIP = None
      srcPort = None
      dstIP = None
      dstPort = None
      state = "UNKNOWN"
      parentObject = None
      currentObject = None
      parentMessage = None
      messages = []
      #if('natural' in values.keys() and  # there is property 'natural'
       #  values['natural'] == 'peak'): #  and it's value is 'peak'
      #  if('name' in values.keys() and values['name'] == u'Latschenkopf'):
       #   printAll = True
        #processNode(values, outFile, float(input.tell())/float(inputFileSize)*100.0, nodes, startTime)
      #values = {}
    #elif(tokens[0] == u'<tag'):
     # tagLineToKeyValuePairs(tokens[1:], values)
    elif(tokens[0] == u'<proto'):
      if(tokens[1] == u'name="geninfo"'):
        state = "geninfo"
      elif(tokens[1] == u'name="ip"'):
        state = "ip"
      elif(tokens[1] == u'name="tcp"'):
        state = "tcp"
      elif(tokens[1] == u'name="whatsapp"'):
        state = "whatsapp"
    elif(tokens[0] == u'<field'):
      if(state == "geninfo"):
        if(tokens[1] == u'name="num"'):
          for token in tokens:
            if(u'show="' in token):
              packetNumber = token.split('"')[1]
          sys.stdout.write("%s: " % packetNumber)
      if(state == "ip"):
        if(tokens[1] == u'name="ip.src"'):
          for token in tokens:
            if(u'show="' in token):
              srcIP = token.split('"')[1]
          sys.stdout.write("%s -> " % srcIP)
        if(tokens[1] == u'name="ip.dst"'):
          for token in tokens:
            if(u'show="' in token):
              dstIP = token.split('"')[1]
          sys.stdout.write("%s, " % dstIP)
      if(state == "tcp"):
        if(tokens[1] == u'name="tcp.srcport"'):
          for token in tokens:
            if(u'show="' in token):
              srcPort = token.split('"')[1]
          sys.stdout.write("%s -> " % srcPort)
        if(tokens[1] == u'name="tcp.dstport"'):
          for token in tokens:
            if(u'show="' in token):
              dstPort = token.split('"')[1]
          sys.stdout.write("%s\n" % dstPort)
      if(state == "whatsapp"):
        if(tokens[1] == u'name="whatsapp.message"' and tokens[-1][-2:] != u'/>'):
          message = Message(packetNumber, messageNumber)
          figureOutDirection(srcIP, srcPort, dstIP, dstPort, message)
          messageNumber += 1
          if(debug):
            sys.stderr.write("Message created at %d\n" % id(message))
          message.parent = currentObject
          messages.append(message)
          parentObject = currentObject
          currentObject = message
          parentMessage = message
        elif(tokens[1] == u'name="whatsapp.node"'):
          node = Node()
          if(debug):
            sys.stderr.write("Node created at %d\n" % id(node))
          if(currentObject == None or currentObject.type != 'node'):
            node.parent = parentMessage
          else:
            node.parent = currentObject
          node.type = 'node'
          node.parent.nodes.append(node)
          if(debug):
            sys.stderr.write("Node appended to parent at %d\n" % id(node.parent))
          parentObject = currentObject
          currentObject = node
        elif(tokens[1] == u'name="whatsapp.attr"'):
          attribute = Node()
          if(debug):
            sys.stderr.write("Attribute created at %d\n" % id(attribute))
          attribute.parent = currentObject
          attribute.type = 'attribute'
          attribute.parent.attributes.append(attribute)
          if(debug):
            sys.stderr.write("Attribute apended to parent at %d %d\n" % (id(attribute.parent), id(currentObject)))
          parentObject = currentObject
          currentObject = attribute
        elif(tokens[1] == u'name="whatsapp.userserver"'):
          userserver = Node()
          if(debug):
            sys.stderr.write("Node (userserver) created at %d\n" % id(userserver))
          userserver.parent = currentObject
          userserver.type = 'userserver'
          parentObject = currentObject
          currentObject = userserver
        else:
          empty_node = Node()
          if(debug):
            sys.stderr.write("Node (empty) created at %d\n" % id(empty_node))
          empty_node.parent = currentObject
          empty_node.type = tokens[1]
          parentObject = currentObject
          currentObject = empty_node
          if(tokens[1] == u'name="whatsapp.keyenc15"'):
            parentObject.key = tokens[3]
          if(tokens[1] == u'name="whatsapp.keyencext15"'):
            parentObject.key = tokens[3]
            if(tokens[7] == u'(87)"'):
              parentObject.key = u'Replaced by new connection'
          if(tokens[1] == u'name="whatsapp.keyplain"'):
            parentObject.key = tokens[3][:-1]
          if(tokens[1] == u'name="whatsapp.tagplain"'):
            parentObject.key = tokens[3][:-1]
          if(tokens[1] == u'name="whatsapp.valueenc15"'):
            parentObject.value = tokens[3]
          if(tokens[1] == u'name="whatsapp.valueencext15"'):
            parentObject.value = tokens[3]
            if(parentObject.type == 'userserver'):
              parentObject.parent.value += u'@%s' % tokens[3]
          if(tokens[1] == u'name="whatsapp.nibbleencoded15"'):
            parentObject.value = tokens[5][1:-2]
            if(parentObject.type == 'userserver'):
              parentObject.parent.value = tokens[5][1:-2]
          if(tokens[1] == u'name="whatsapp.valueplain"'):
            parentObject.value = tokens[3][:-1]
          if(tokens[1] == u'name="whatsapp.nodevalueplain"'):
            for token in tokens:
              if(u'value="' in token):
                parentObject.value = token.split('"')[1]
                break;
        if(tokens[-1][-2:] == u'/>'):
          # single tag
          if(parentObject != None):
            parentObject = parentObject.parent
          if(currentObject != None):
            currentObject = currentObject.parent
        else:
          # will have children (going deeper), set current message/node as parent
          #parentObject = currentObject
          #currentObject = None
          pass
    elif(tokens[0] == u'</field>'):
      if(state == "whatsapp"):
        # getting out of the rabbit hole, set parent node as parent
        if(parentObject != None):
          parentObject = parentObject.parent
        if(currentObject != None):
          currentObject = currentObject.parent
    else:
      # skipping all other tags
      pass
    if(debug):
      sys.stderr.write('after:  currentObject %s %s\n' % (currentObject.__class__.__name__, currentObject.type if (currentObject.__class__.__name__ == 'Node') else u''))
      sys.stderr.write('after:  parentObject  %s %s\n' % (parentObject.__class__.__name__, parentObject.type if (parentObject.__class__.__name__ == 'Node') else u''))
  
  # generating clients' and servers' tables
  outputFile.write('''
	</table>
    <div class="endpointTable" style="top: 0;">
      clients: <br>\n''')
  for key in sorted(clients.keys()):
    outputFile.write('<span id="%s" style="background-color: %s; width: 20px;">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span> %s <br>\n' % (key, clients[key], key))
  outputFile.write('''
    </div>
    <div class="endpointTable" style="bottom: 0;">
      servers: <br>\n''')
  for key in sorted(servers.keys()):
    outputFile.write('<span id="%s" style="background-color: %s; width: 20px;">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span> %s <br>\n' % (key, servers[key], key))
  outputFile.write('''
    </div>
  </body>
</html>\n''')
  outputFile.close()

def main():
  if(len(sys.argv) != 2):
    print_help(sys.stderr)
    exit(1)
    
  convertPDML(sys.argv[1])
  

if (__name__ == "__main__"):
  main()
  