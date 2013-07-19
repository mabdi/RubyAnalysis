require 'rgl/base'
require 'rgl/adjacency'
require 'rgl/mutable'
require 'rgl/dot'
require 'rgl/connected_components'

############ constants
FCG_FILENAME = 'mrd_fcg.fuzz'
CFG_PRE = 'mrd_cfg_'
CFG_POST = '.fuzz'
ST_PRE = 'mrd_st_'
ST_POST = '.fuzz'
ET_PRE = 'mrd_et_'
ET_POST = '.fuzz'

## END OF CONSTANTS
####################################################
############ classes
class String
def black;          "\033[30m#{self}\033[0m" end
def red;            "\033[31m#{self}\033[0m" end
def green;          "\033[32m#{self}\033[0m" end
def  brown;         "\033[33m#{self}\033[0m" end
def blue;           "\033[34m#{self}\033[0m" end
def magenta;        "\033[35m#{self}\033[0m" end
def cyan;           "\033[36m#{self}\033[0m" end
def gray;           "\033[37m#{self}\033[0m" end
def bg_black;       "\033[40m#{self}\0330m"  end
def bg_red;         "\033[41m#{self}\033[0m" end
def bg_green;       "\033[42m#{self}\033[0m" end
def bg_brown;       "\033[43m#{self}\033[0m" end
def bg_blue;        "\033[44m#{self}\033[0m" end
def bg_magenta;     "\033[45m#{self}\033[0m" end
def bg_cyan;        "\033[46m#{self}\033[0m" end
def bg_gray;        "\033[47m#{self}\033[0m" end
def bold;           "\033[1m#{self}\033[22m" end
def reverse_color;  "\033[7m#{self}\033[27m" end
end

## END OF CLASSES
###############################################################################
############ functions
def l(s)
        if(@dolog == true)
                puts (Time.new.strftime("%H:%M:%S") +": " + s.to_s).blue.bold
        end
end
def readargs
	ARGV.each do|a|
		if a.include? 'l'
			@dolog = true
		else
		  	@dolog = false
		end
		if a.include? 'g'
			@graph = true
		else
			@graph = false
		end
		if a.include? 'c'
			@cyc = true
		else
			@cyc = false
		end
	end
l "-----------------<<<START at  #{Time.new.strftime("%Y-%m-%d") }>>>--------------"
end

def getFCG
	dg = RGL::DirectedAdjacencyGraph[]
	i=0
	start = ""
	File.open(FCG_FILENAME).each_line do |line|
		ns = line.split
		dg.add_edge ns[0], ns[1]
		if i == 0 then start = ns[0]
		i = i+1
	end
l 'GRAPH CREATED'
return dg,start
end	
def draw(dg,name)
	if @graph == true
		dg.write_to_graphic_file 'png',name
l 'GRAP DRWANED'
	end
end

def findCycles(dg)
	components = dg.strongly_connected_components
	toremove = Array.new
	vs = components.comp_map.values.clone.sort
	if(vs[0] != vs[1])then  toremove.push vs[0] end
	if(vs[vs.size - 1] != vs[vs.size - 2 ]) then toremove.push vs[vs.size-1] end
	if(vs.size > 2)
		(vs.size - 2).times{ |i|
			if(vs[i] != vs[i+1] && vs[i+1] != vs[i+2])
				toremove.push vs[i+1]
			end
		}
	end
	cycles = Array.new
	vs.uniq.each{ |v|
		if !toremove.include? v
			cycles.push components.comp_map.select{ |k2,v2| v2==v}.keys
		end
	}

	l "CYCLES FOUND count: #{cycles.size}"
	return cycles
end
def sortDAG (s , a , dg , r ,  b)
        b.push s
        nx = dg.edges.select { |e| e.source == s }.map {|e| e.target}
        nx.each { |n|
                if a.include? n then next end
                if b.include? n  then
                        r.push s
                        next
                end
                sortDAG n , a , dg , r , b
        }
        a.push s
        b.pop
end
def analyseFun func
	
end
def analyse
	readargs
	fcg,fcgh = getFCG
	draw fcg,'fcg'
	functions = Array.new
	tmp = Array.new
	recs = Array.new
	sortDAG fcgh,functions,fcg,recs,tmp
	functions.each { |func|
		analyseFun func
	}
end
## END OF FUNCTIONS
###############################################################################
########## main
analyse
