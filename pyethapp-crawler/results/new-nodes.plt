set terminal png nocrop enhanced size 1600,1200 font "arial,28"
unset key
set datafile separator ","
set output outfile
set style line 1 lc rgb '#ff0000' lt 1 lw 2 pt 7 ps 1

set logscale x
set xlabel 'iteration'
set ylabel 'number of new nodes'
set grid

plot input using 0:1 with linespoints ls 1
