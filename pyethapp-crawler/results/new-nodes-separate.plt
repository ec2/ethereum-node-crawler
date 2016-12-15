set terminal png nocrop enhanced size 1600,1200 font "arial,28"
set datafile separator ","
set output outfile
set style line 1 lc rgb '#0060ad' lt 1 lw 2 pt 7 ps 1

set logscale x
set xlabel 'iteration in logscale'
set ylabel 'number of new nodes'
set grid

plot input1 using 0:1 with linespoints ls 1 notitle
